import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeHighlight from 'rehype-highlight';
import {
  AlertCircle,
  ArrowRight,
  Bot,
  CornerDownLeft,
  Globe2,
  Mic,
  MicOff,
  RefreshCw,
  Sparkles,
  Square,
  X,
} from 'lucide-react';
import {
  fetchCapabilities,
  fetchGnaniTTSAudio,
  startScan,
  streamAssistantChat,
  streamTTS,
  transcribeVoice,
  type AssistantHistoryMessage,
  type AppCapabilities,
  type AssistantStreamResult,
} from '../api';
import type { AssistantMessage, NavigationIntent, Scan } from '../types';
import { parseNavigationIntent } from '../utils/navigationIntent';

type VoiceState = 'idle' | 'listening' | 'processing' | 'speaking' | 'error' | 'interrupted';
type AssistantMode = 'voice' | 'text';

interface AssistantHeroProps {
  isOpen: boolean;
  onClose: () => void;
  onExploreDashboard: () => void;
  onNavigateRequest: (intent: NavigationIntent) => { success: boolean; message?: string };
  onScanLaunched: (scan: Scan) => void;
  activeScan: Scan | null;
}

const PHASE_LABEL: Record<string, string> = {
  IDLE: 'AWAITING TOPIC',
  awaiting_topic: 'AWAITING TOPIC',
  confirm_domain: 'CONFIRM DOMAIN',
  CONFIRM_DOMAIN: 'CONFIRM DOMAIN',
  awaiting_auth: 'AUTHORIZATION',
  AWAITING_AUTH: 'AUTHORIZATION',
  authorized: 'AUTHORIZED',
  AUTHORIZED: 'AUTHORIZED',
  scan_followup: 'SCAN FOLLOW-UP',
  SCAN_FOLLOWUP: 'SCAN FOLLOW-UP',
  general_chat: 'OPEN CONVERSATION',
};

const PROMPT_SHELF: ReadonlyArray<{ label: string; message: string }> = [
  { label: 'Scan example.com', message: 'Please scan example.com for me.' },
  { label: 'Critical findings?', message: 'What are my critical findings?' },
  { label: 'Show asset inventory', message: 'Show me the asset inventory for the latest scan.' },
  { label: 'Open attack graph', message: 'Open the attack graph for the active scan.' },
  { label: 'Summarize this scan', message: 'Summarize the latest scan results.' },
];

const STORAGE_PREFIX = 'eg:assistant:';

function storageKeyFor(scan: Scan | null): string {
  return `${STORAGE_PREFIX}${scan?.id ?? 'default'}`;
}

function uid(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function stripMarkdownToPlainText(markdown: string): string {
  // Minimal markdown stripping so TTS gets a clean narration string.
  return markdown
    .replace(/```[\s\S]*?```/g, ' code block ')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/!\[[^\]]*\]\([^)]+\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/^\s*[-*]\s+/gm, '')
    .replace(/\|/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function encodeWAV(samples: Float32Array, sampleRate: number): Blob {
  const buffer = new ArrayBuffer(44 + samples.length * 2);
  const view = new DataView(buffer);
  view.setUint32(0, 0x52494646, false); // "RIFF"
  view.setUint32(4, 36 + samples.length * 2, true);
  view.setUint32(8, 0x57415645, false); // "WAVE"
  view.setUint32(12, 0x666d7420, false); // "fmt "
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true); // PCM
  view.setUint16(22, 1, true); // mono
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  view.setUint32(36, 0x64617461, false); // "data"
  view.setUint32(40, samples.length * 2, true);
  let offset = 44;
  for (let i = 0; i < samples.length; i++, offset += 2) {
    const s = Math.max(-1, Math.min(1, samples[i]));
    view.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7fff, true);
  }
  return new Blob([buffer], { type: 'audio/wav' });
}

// ---------------------------------------------------------------------------
// useStreamingAssistant — owns the AbortController for in-flight chat + TTS
// requests so the caption-stop button can interrupt them atomically.
// ---------------------------------------------------------------------------

interface StreamingController {
  abort: () => void;
  stream: (
    message: string,
    currentState: string,
    currentDomain: string | undefined,
    detectedLanguage: string | undefined,
    onToken: (chunk: string, replace?: boolean) => void,
    conversationHistory: AssistantHistoryMessage[],
  ) => Promise<AssistantStreamResult>;
}

function useStreamingAssistant(scanId?: number): StreamingController {
  const abortRef = useRef<AbortController | null>(null);

  const abort = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
    }
  }, []);

  const stream = useCallback<StreamingController['stream']>(
    async (message, currentState, currentDomain, detectedLanguage, onToken, conversationHistory) => {
      abort();
      const controller = new AbortController();
      abortRef.current = controller;
      try {
        return await streamAssistantChat(
          message,
          currentState,
          scanId,
          currentDomain,
          detectedLanguage,
          onToken,
          controller.signal,
          conversationHistory,
        );
      } finally {
        if (abortRef.current === controller) abortRef.current = null;
      }
    },
    [abort, scanId],
  );

  useEffect(() => () => abort(), [abort]);

  return { abort, stream };
}

// ---------------------------------------------------------------------------
// Audio-reactive orb — AnalyserNode on either the mic stream or TTS audio.
// ---------------------------------------------------------------------------

interface OrbController {
  attachStream: (stream: MediaStream | null) => void;
  playAudioBuffer: (buffer: ArrayBuffer) => Promise<void>;
  stopAudio: () => void;
}

function useAudioOrb(orbRef: React.RefObject<HTMLDivElement | null>, enabled: boolean): OrbController {
  const audioCtxRef = useRef<AudioContext | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const sourceRef = useRef<AudioBufferSourceNode | null>(null);
  const micSourceRef = useRef<MediaStreamAudioSourceNode | null>(null);
  const gainRef = useRef<GainNode | null>(null);
  const rafRef = useRef<number | null>(null);
  const levelRef = useRef(0);

  const ensureContext = useCallback(() => {
    if (audioCtxRef.current) return audioCtxRef.current;
    const Ctor = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctor) return null;
    const ctx = new Ctor();
    const analyser = ctx.createAnalyser();
    analyser.fftSize = 256;
    const gain = ctx.createGain();
    gain.gain.value = 1;
    // NOTE: analyser is strictly for frequency measurement — DO NOT connect analyser to destination!
    gain.connect(ctx.destination);
    audioCtxRef.current = ctx;
    analyserRef.current = analyser;
    gainRef.current = gain;
    return ctx;
  }, []);

  // rAF loop drives audio-reactive scale on the outer orb wrapper
  useEffect(() => {
    const loop = () => {
      let target = 0;
      if (analyserRef.current) {
        const data = new Uint8Array(analyserRef.current.frequencyBinCount);
        analyserRef.current.getByteFrequencyData(data);
        let sum = 0;
        for (let i = 0; i < data.length; i++) sum += data[i];
        target = sum / data.length / 255;
      }
      levelRef.current = levelRef.current * 0.85 + target * 0.15;
      if (orbRef.current && enabled) {
        const scale = 1 + Math.min(0.45, levelRef.current * 0.5);
        orbRef.current.style.transform = `scale(${scale.toFixed(3)})`;
      }
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    };
  }, [orbRef, enabled]);

  const attachStream = useCallback(
    (stream: MediaStream | null) => {
      const ctx = ensureContext();
      if (!ctx || !analyserRef.current) return;
      if (micSourceRef.current) {
        try { micSourceRef.current.disconnect(); } catch { /* ignore */ }
        micSourceRef.current = null;
      }
      if (!stream) return;
      try {
        const src = ctx.createMediaStreamSource(stream);
        // Connect mic stream ONLY to analyser for visual animation — NEVER to speakers!
        src.connect(analyserRef.current);
        micSourceRef.current = src;
      } catch {
        /* ignore */
      }
    },
    [ensureContext],
  );

  const stopAudio = useCallback(() => {
    if (sourceRef.current) {
      try { sourceRef.current.stop(); } catch { /* ignore */ }
      try { sourceRef.current.disconnect(); } catch { /* ignore */ }
      sourceRef.current = null;
    }
  }, []);

  const playAudioBuffer = useCallback(
    (buffer: ArrayBuffer): Promise<void> => {
      return new Promise<void>((resolve) => {
        const ctx = ensureContext();
        if (!ctx || !analyserRef.current || !gainRef.current) {
          resolve();
          return;
        }
        if (ctx.state === 'suspended') {
          void ctx.resume();
        }
        stopAudio();
        ctx.decodeAudioData(
          buffer.slice(0),
          (decoded) => {
            try {
              const src = ctx.createBufferSource();
              src.buffer = decoded;
              src.connect(analyserRef.current!);
              src.connect(gainRef.current!);
              src.onended = () => {
                sourceRef.current = null;
                resolve();
              };
              src.start();
              sourceRef.current = src;
            } catch {
              resolve();
            }
          },
          () => {
            resolve();
          },
        );
      });
    },
    [ensureContext, stopAudio],
  );

  useEffect(() => {
    return () => {
      stopAudio();
      if (micSourceRef.current) {
        try { micSourceRef.current.disconnect(); } catch { /* ignore */ }
      }
      if (audioCtxRef.current && audioCtxRef.current.state !== 'closed') {
        void audioCtxRef.current.close();
      }
    };
  }, [stopAudio]);

  return { attachStream, playAudioBuffer, stopAudio };
}

// ---------------------------------------------------------------------------

export const AssistantHero: React.FC<AssistantHeroProps> = ({
  isOpen,
  onClose,
  onExploreDashboard,
  onNavigateRequest,
  onScanLaunched,
  activeScan,
}) => {
  const [voiceState, setVoiceState] = useState<VoiceState>('idle');
  const [mode, setMode] = useState<AssistantMode>('voice');
  const [messages, setMessages] = useState<AssistantMessage[]>([]);
  const [conversationState, setConversationState] = useState<string>('IDLE');
  const [currentDomain, setCurrentDomain] = useState<string | null>(null);
  const [textInput, setTextInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [capabilities, setCapabilities] = useState<AppCapabilities | null>(null);
  const [continuousListening, setContinuousListening] = useState<boolean>(false);
  const continuousListeningRef = useRef<boolean>(false);
  continuousListeningRef.current = continuousListening;

  const orbRef = useRef<HTMLDivElement | null>(null);
  const transcriptEndRef = useRef<HTMLDivElement | null>(null);

  const pcmSamplesRef = useRef<Float32Array[]>([]);
  const recCtxRef = useRef<AudioContext | null>(null);
  const recProcessorRef = useRef<ScriptProcessorNode | null>(null);
  const speechRecRef = useRef<any>(null);
  const webSpeechTranscriptRef = useRef<string>('');
  const micStreamRef = useRef<MediaStream | null>(null);
  const pendingTranscribeRef = useRef<AbortController | null>(null);
  const silenceTimerRef = useRef<any>(null);
  const startListeningRef = useRef<() => Promise<void>>(async () => {});
  const voiceStateRef = useRef<VoiceState>(voiceState);
  voiceStateRef.current = voiceState;

  const storageKey = useMemo(() => storageKeyFor(activeScan), [activeScan]);
  const { stream: streamAssistant, abort: abortAssistant } = useStreamingAssistant(activeScan?.id);
  const orb = useAudioOrb(orbRef, isOpen);

  // Capabilities + provider label.
  useEffect(() => {
    let active = true;
    fetchCapabilities()
      .then((caps) => { if (active) setCapabilities(caps); })
      .catch(() => { if (active) setCapabilities(null); });
    return () => { active = false; };
  }, []);

  // Restore messages from localStorage when the active scan changes.
  useEffect(() => {
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) {
        const parsed = JSON.parse(raw) as AssistantMessage[];
        if (Array.isArray(parsed)) {
          setMessages(parsed.filter((message) => message.role === 'user' || message.content.trim()));
          return;
        }
      }
    } catch { /* ignore */ }
    setMessages([]);
  }, [storageKey]);

  // Persist messages (last 60) keyed by scan.
  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(messages.slice(-60)));
    } catch { /* ignore quota */ }
  }, [storageKey, messages]);

  // Auto-scroll the transcript to the latest message.
  useEffect(() => {
    if (transcriptEndRef.current) {
      transcriptEndRef.current.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }
  }, [messages]);

  // Reset transient state when the assistant is closed.
  useEffect(() => {
    if (!isOpen) {
      setContinuousListening(false);
      continuousListeningRef.current = false;
      if (silenceTimerRef.current) clearTimeout(silenceTimerRef.current);
      stopMic();
      abortAssistant();
      orb.stopAudio();
      setVoiceState('idle');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  const ttsProviderTag = capabilities?.tts?.model
    ? `Timbre · ${capabilities.tts.model}`
    : 'Timbre · TTS';

  const updateLastAssistant = useCallback((id: string, patch: Partial<AssistantMessage>) => {
    setMessages((prev) => prev.map((m) => (m.id === id ? { ...m, ...patch } : m)));
  }, []);

  const finalizeAssistantReply = useCallback(
    (id: string, markdown: string) => {
      updateLastAssistant(id, { markdown, content: markdown });
    },
    [updateLastAssistant],
  );

  // Speak the assistant reply via TTS (Gnani Timbre with browser speech synthesis fallback).
  const speakReply = useCallback(
    async (markdown: string) => {
      const text = stripMarkdownToPlainText(markdown);
      if (!text) {
        setVoiceState('idle');
        if (continuousListeningRef.current) {
          setTimeout(() => {
            if (continuousListeningRef.current) void startListeningRef.current();
          }, 300);
        }
        return;
      }
      setVoiceState('speaking');
      const onFinishedPlayback = () => {
        setVoiceState('idle');
        if (continuousListeningRef.current) {
          setTimeout(() => {
            if (continuousListeningRef.current) void startListeningRef.current();
          }, 400);
        }
      };

      try {
        // Attempt 1: Stream TTS from Gnani
        const chunks: ArrayBuffer[] = [];
        for await (const chunk of streamTTS(text, capabilities?.tts?.voice ?? 'Nalini', 1.0)) {
          chunks.push(chunk);
        }
        if (chunks.length > 0) {
          const total = chunks.reduce((acc, c) => acc + c.byteLength, 0);
          const merged = new Uint8Array(total);
          let offset = 0;
          for (const c of chunks) {
            merged.set(new Uint8Array(c), offset);
            offset += c.byteLength;
          }
          await orb.playAudioBuffer(merged.buffer);
          onFinishedPlayback();
          return;
        }
        // Attempt 2: Blob TTS from Gnani
        const blob = await fetchGnaniTTSAudio(text, capabilities?.tts?.voice ?? 'Nalini', 1.0);
        await orb.playAudioBuffer(await blob.arrayBuffer());
        onFinishedPlayback();
        return;
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') return;
        // Fallback: browser speech synthesis
        if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
          try {
            window.speechSynthesis.cancel();
            const utterance = new SpeechSynthesisUtterance(text);
            utterance.rate = 1.0;
            utterance.onend = () => onFinishedPlayback();
            utterance.onerror = () => onFinishedPlayback();
            window.speechSynthesis.speak(utterance);
            return;
          } catch {
            /* ignore */
          }
        }
        onFinishedPlayback();
      }
    },
    [capabilities, orb],
  );

  // ---- Conversation plumbing -------------------------------------------------

  const sendUserMessage = useCallback(
    async (rawText: string, lang?: string) => {
      const text = rawText.trim();
      if (!text) return;
      setError(null);

      const userMessage: AssistantMessage = {
        id: uid('user'),
        role: 'user',
        content: text,
        timestamp: Date.now(),
        detected_language: lang,
      };
      const assistantId = uid('assistant');
      const assistantPlaceholder: AssistantMessage = {
        id: assistantId,
        role: 'assistant',
        content: '',
        markdown: '',
        timestamp: Date.now(),
      };
      setMessages((prev) => [...prev, userMessage, assistantPlaceholder]);
      setVoiceState('processing');

      try {
        const history = messages
          .filter((message) => message.content.trim())
          .slice(-12)
          .map(({ role, content }) => ({ role, content }));
        const result = await streamAssistant(text, conversationState, currentDomain ?? undefined, lang, (token, replace) => {
          setMessages((prev) => prev.map((m) => {
            if (m.id !== assistantId) return m;
            const next = replace ? token : (m.markdown ?? '') + token;
            return { ...m, markdown: next, content: next };
          }));
        }, history);
        const finalMarkdown = result.markdown ?? result.reply ?? '';
        finalizeAssistantReply(
          assistantId,
          finalMarkdown.trim() || "I couldn't form a reply just now. Please try asking again.",
        );
        setConversationState(result.next_state);
        if (result.domain !== undefined) setCurrentDomain(result.domain || null);

        if (!finalMarkdown.trim()) {
          setError('The assistant returned an empty reply. Please try again.');
          setVoiceState('error');
          return;
        }
        // If the assistant reply mentions a dashboard page, route the user there.
        const intent = parseNavigationIntent(finalMarkdown);
        if (intent && intent.page !== 'assistant') {
          const outcome = onNavigateRequest(intent);
          if (!outcome.success && outcome.message) {
            setError(outcome.message);
          }
        } else if (result.can_launch && result.domain && result.authorization_token) {
          // The assistant pre-authorized a domain; offer to launch the scan.
          try {
            const scan = await startScan(result.domain, true, result.authorization_token);
            onScanLaunched(scan);
          } catch {
            // Soft-fail: the reply is still visible.
          }
        }

        // Speak the reply when TTS is configured (or the endpoint is enabled).
        if (finalMarkdown) {
          await speakReply(finalMarkdown);
        } else {
          setVoiceState('idle');
        }
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') {
          setVoiceState('interrupted');
          return;
        }
        const message = err instanceof Error ? err.message : 'Assistant unavailable.';
        setError(message);
        setVoiceState('error');
      }
    },
    [conversationState, currentDomain, messages, finalizeAssistantReply, onNavigateRequest, onScanLaunched, speakReply, streamAssistant],
  );

  // ---- Mic capture (push-to-talk with Web Speech API & WAV encoding) --------

  const stopMic = useCallback(() => {
    if (silenceTimerRef.current) {
      clearTimeout(silenceTimerRef.current);
      silenceTimerRef.current = null;
    }
    if (speechRecRef.current) {
      try { speechRecRef.current.stop(); } catch { /* ignore */ }
      speechRecRef.current = null;
    }
    if (recProcessorRef.current) {
      try { recProcessorRef.current.disconnect(); } catch { /* ignore */ }
      recProcessorRef.current = null;
    }
    if (recCtxRef.current && recCtxRef.current.state !== 'closed') {
      try { void recCtxRef.current.close(); } catch { /* ignore */ }
      recCtxRef.current = null;
    }
    if (micStreamRef.current) {
      micStreamRef.current.getTracks().forEach((track) => track.stop());
      micStreamRef.current = null;
    }
    orb.attachStream(null);
  }, [orb]);

  const startListening = useCallback(async () => {
    if (voiceState === 'listening') return;
    setError(null);
    webSpeechTranscriptRef.current = '';
    pcmSamplesRef.current = [];
    if (silenceTimerRef.current) {
      clearTimeout(silenceTimerRef.current);
      silenceTimerRef.current = null;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      micStreamRef.current = stream;
      orb.attachStream(stream);

      // Start Web Speech API in parallel (instant accurate browser STT with auto-silence VAD)
      const SpeechRec = (window as unknown as { SpeechRecognition?: any; webkitSpeechRecognition?: any }).SpeechRecognition ||
        (window as unknown as { webkitSpeechRecognition?: any }).webkitSpeechRecognition;
      if (SpeechRec) {
        try {
          const recognizer = new SpeechRec();
          recognizer.continuous = true;
          recognizer.interimResults = true;
          recognizer.lang = 'en-US';
          recognizer.onresult = (event: any) => {
            const transcript = Array.from(event.results)
              .map((r: any) => r[0].transcript)
              .join(' ');
            if (transcript) {
              webSpeechTranscriptRef.current = transcript;
            }

            // Auto-detect speech pause (VAD): when user speaks, set a 1.4s silence timer to auto-send
            if (continuousListeningRef.current && transcript.trim()) {
              if (silenceTimerRef.current) clearTimeout(silenceTimerRef.current);
              silenceTimerRef.current = setTimeout(() => {
                if (webSpeechTranscriptRef.current.trim()) {
                  stopListening();
                }
              }, 1400);
            }
          };
          recognizer.onerror = () => {
            /* ignore Web Speech error and rely on PCM WAV */
          };
          recognizer.onend = () => {
            // If in continuous mode and listening was stopped by browser timeout without text, restart
            if (continuousListeningRef.current && voiceStateRef.current === 'listening' && !webSpeechTranscriptRef.current.trim()) {
              try { recognizer.start(); } catch { /* ignore */ }
            }
          };
          recognizer.start();
          speechRecRef.current = recognizer;
        } catch {
          /* ignore Web Speech startup failure */
        }
      }

      // Record PCM Float32 samples via AudioContext to generate 16-bit 16kHz WAV
      const Ctor = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
      if (Ctor) {
        const aCtx = new Ctor({ sampleRate: 16000 });
        const source = aCtx.createMediaStreamSource(stream);
        const processor = aCtx.createScriptProcessor(4096, 1, 1);
        processor.onaudioprocess = (e) => {
          const input = e.inputBuffer.getChannelData(0);
          pcmSamplesRef.current.push(new Float32Array(input));
        };
        source.connect(processor);
        processor.connect(aCtx.destination);
        recCtxRef.current = aCtx;
        recProcessorRef.current = processor;
      }

      setVoiceState('listening');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Microphone access denied.');
      setVoiceState('error');
    }
  }, [voiceState, orb]);
  startListeningRef.current = startListening;

  const stopListening = useCallback(() => {
    if (voiceState !== 'listening') return;

    const webTranscript = webSpeechTranscriptRef.current.trim();
    const recordedChunks = [...pcmSamplesRef.current];
    const recCtx = recCtxRef.current;
    stopMic();

    // If Web Speech API already transcribed the speech, use it immediately
    if (webTranscript) {
      setVoiceState('processing');
      void sendUserMessage(webTranscript);
      return;
    }

    // Otherwise, encode recorded PCM into 16-bit 16kHz WAV and send to Gnani STT
    if (recordedChunks.length > 0 && recCtx) {
      const totalLen = recordedChunks.reduce((acc, c) => acc + c.length, 0);
      // If audio is under ~0.3s (too short or silent click), don't treat as hard error
      if (totalLen < 4800) {
        setVoiceState('idle');
        return;
      }
      setVoiceState('processing');
      const merged = new Float32Array(totalLen);
      let offset = 0;
      for (const c of recordedChunks) {
        merged.set(c, offset);
        offset += c.length;
      }
      const wavBlob = encodeWAV(merged, recCtx.sampleRate || 16000);

      const ctrl = new AbortController();
      pendingTranscribeRef.current = ctrl;
      transcribeVoice(wavBlob)
        .then((result) => {
          if (!result.success || !result.transcript) {
            // If empty transcript (e.g. silence or quiet room), return to idle gracefully
            if (!result.transcript) {
              setVoiceState('idle');
              return;
            }
            throw new Error(result.error || 'Could not transcribe speech.');
          }
          void sendUserMessage(result.transcript, result.detected_language);
        })
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === 'AbortError') return;
          setError(err instanceof Error ? err.message : 'Transcription failed. Please type your query.');
          setVoiceState('error');
        })
        .finally(() => {
          pendingTranscribeRef.current = null;
        });
      return;
    }

    setVoiceState('idle');
  }, [voiceState, stopMic, sendUserMessage]);

  // Interrupt whatever is currently playing/processing — pause TTS, abort any
  // in-flight chat/transcription, drop back to idle so a new turn can begin.
  const handleInterrupt = useCallback(() => {
    orb.stopAudio();
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      try { window.speechSynthesis.cancel(); } catch { /* ignore */ }
    }
    abortAssistant();
    if (pendingTranscribeRef.current) pendingTranscribeRef.current.abort();
    setVoiceState('interrupted');
    window.setTimeout(() => setVoiceState((s) => (s === 'interrupted' ? 'idle' : s)), 250);
  }, [orb, abortAssistant]);

  // ---- Text input -----------------------------------------------------------

  const submitText = useCallback(() => {
    const value = textInput.trim();
    if (!value) return;
    setTextInput('');
    void sendUserMessage(value);
  }, [textInput, sendUserMessage]);

  // ---- Prompt shelf ---------------------------------------------------------

  const handlePromptClick = useCallback((message: string) => {
    void sendUserMessage(message);
  }, [sendUserMessage]);

  const handleRetry = useCallback(() => {
    setError(null);
    setVoiceState('idle');
  }, []);

  const phaseLabel = PHASE_LABEL[conversationState] ?? 'OPEN CONVERSATION';
  const phaseClass = conversationState.replace(/_/g, '-');
  const showOnboard = messages.length === 0;
  const stateDotClass = voiceState === 'idle' ? '' : `state-dot-${voiceState}`;
  const stateCopy: Record<VoiceState, { title: string; sub: string }> = {
    idle: { title: 'Ready to assist', sub: 'Tap the mic or type a question.' },
    listening: { title: 'Listening', sub: 'Release to send for transcription.' },
    processing: { title: 'Processing', sub: 'Routing your request through the assistant.' },
    speaking: { title: 'Speaking', sub: 'Replaying the reply via Timbre TTS.' },
    error: { title: 'Something broke', sub: 'Review the error and try again.' },
    interrupted: { title: 'Interrupted', sub: 'Stopped the previous turn.' },
  };
  const stateInfo = stateCopy[voiceState];

  return (
    <section className="assistant-page" aria-labelledby="assistant-heading" data-state={voiceState}>
      <div className="assistant-heading">
        <div className="assistant-heading-copy">
          <div className="assistant-kicker">
            <Sparkles aria-hidden="true" />
            VOICE-FIRST SECURITY
            <i aria-hidden="true" />
          </div>
          <h2 id="assistant-heading">
            Ask the <em>assistant</em>.
          </h2>
          <p>
            Authorize a domain, surface findings, or open any page in the dashboard. The assistant
            streams its reply, narrates it via Timbre TTS, and can route you directly to the
            evidence you asked about.
          </p>
        </div>
        <div className="assistant-heading-actions">
          <div className="assistant-mode-selector" role="tablist" aria-label="Assistant input mode">
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'voice'}
              className={`assistant-mode-button ${mode === 'voice' ? 'is-active' : ''}`}
              onClick={() => setMode('voice')}
            >
              <Mic aria-hidden="true" /> Voice
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'text'}
              className={`assistant-mode-button ${mode === 'text' ? 'is-active' : ''}`}
              onClick={() => setMode('text')}
            >
              <CornerDownLeft aria-hidden="true" /> Text
            </button>
          </div>
          <button type="button" className="assistant-icon-button" onClick={onExploreDashboard} aria-label="Explore dashboard">
            <Globe2 aria-hidden="true" />
          </button>
          <button type="button" className="assistant-icon-button" onClick={onClose} aria-label="Close assistant">
            <X aria-hidden="true" />
          </button>
        </div>
      </div>

      <div className="assistant-content">
        <div className="assistant-orb-panel" aria-live="polite">
          <div className="assistant-stage-topline">
            <span className="assistant-session-index">
              SESSION
              <i />
              {activeScan ? `SCAN #${activeScan.id}` : 'NO ACTIVE SCAN'}
            </span>
            <span>{phaseLabel}</span>
          </div>

          <div className="orb-stage" aria-hidden="true">
            <div className="orb-rings-wrapper" ref={orbRef}>
              {/* Animated particle ring system */}
              <div className="orb-ring orb-ring-1" />
              <div className="orb-ring orb-ring-2" />
              <div className="orb-ring orb-ring-3" />
              <div className="orb-ring orb-ring-4" />
              {/* Spinning arc segments */}
              <div className="orb-arc orb-arc-a" />
              <div className="orb-arc orb-arc-b" />
              <div className="orb-arc orb-arc-c" />
              {/* Floating particle dots */}
              {[0,1,2,3,4,5,6,7].map(i => (
                <div key={i} className={`orb-particle orb-particle-${i}`} />
              ))}
              {/* Core glow */}
              <div className="orb-core-glow" />
              <div className="orb-core-pulse" />
              <div className="orb-core-label">
                E<span>G</span>
              </div>
            </div>
          </div>

          <div className="assistant-state-block">
            <span className={`assistant-state-indicator ${stateDotClass}`} aria-hidden="true" />
            <div>
              <strong>{stateInfo.title}</strong>
              <small>{stateInfo.sub}</small>
            </div>
          </div>

          <div className="assistant-controls">
            {mode === 'voice' ? (
              <>
                <button
                  type="button"
                  className={`assistant-control-button assistant-control-primary ${
                    voiceState === 'listening' || continuousListening ? 'is-active' : ''
                  }`}
                  onClick={() => {
                    if (continuousListening || voiceState === 'listening') {
                      setContinuousListening(false);
                      continuousListeningRef.current = false;
                      stopListening();
                    } else if (voiceState !== 'processing' && voiceState !== 'speaking') {
                      setContinuousListening(true);
                      continuousListeningRef.current = true;
                      void startListening();
                    }
                  }}
                  disabled={voiceState === 'processing' || voiceState === 'speaking'}
                  aria-label={continuousListening || voiceState === 'listening' ? 'End conversation' : 'Start conversation'}
                >
                  {continuousListening || voiceState === 'listening' ? <MicOff aria-hidden="true" /> : <Mic aria-hidden="true" />}
                  {continuousListening || voiceState === 'listening' ? 'End conversation' : 'Start conversation'}
                </button>
                <button
                  type="button"
                  className="assistant-control-button"
                  onClick={onExploreDashboard}
                >
                  <Globe2 aria-hidden="true" /> Explore dashboard
                </button>
                {(voiceState === 'speaking' || voiceState === 'processing') && (
                  <button
                    type="button"
                    className="assistant-control-button assistant-control-danger"
                    onClick={handleInterrupt}
                    aria-label="Stop audio"
                  >
                    <Square aria-hidden="true" /> Stop audio
                  </button>
                )}
              </>
            ) : (
              <button
                type="button"
                className="assistant-control-button"
                onClick={() => setMode('voice')}
              >
                <Mic aria-hidden="true" /> Switch to voice
              </button>
            )}
          </div>

          <div className="assistant-session-foot">
            <span>
              <i /> {activeScan ? activeScan.target_domain : 'No active scan'}
            </span>
            <button type="button" onClick={onClose}>
              <X aria-hidden="true" /> Close
            </button>
          </div>
        </div>

        <div className="assistant-dialogue">
          <div className="assistant-dialogue-header">
            <div className="dialogue-title-group">
              <span className="dialogue-avatar">
                <Bot aria-hidden="true" />
              </span>
              <div>
                <strong>ExposureGraph Assistant</strong>
                <small>{activeScan ? `Scan #${activeScan.id} · ${activeScan.target_domain}` : 'Awaiting first scan'}</small>
              </div>
            </div>
            <span className={`dialogue-context`}>
              <span className={`phase-mark phase-${phaseClass}`} aria-hidden="true" />
              {phaseLabel}
            </span>
          </div>

          <div className="assistant-message-list" role="log" aria-live="polite" aria-relevant="additions">
            {showOnboard && (
              <div className="assistant-onboard-card">
                <span className="onboard-spark">
                  <Sparkles aria-hidden="true" />
                </span>
                <div>
                  <small>GET STARTED</small>
                  <strong>Talk or type to drive the dashboard.</strong>
                  <p>
                    Use the mic for push-to-talk or switch to text mode. Ask about an active scan,
                    request a domain assessment, or jump straight to findings.
                  </p>
                  <div className="onboard-actions">
                    <button type="button" onClick={onExploreDashboard}>
                      Explore dashboard <ArrowRight aria-hidden="true" />
                    </button>
                  </div>
                </div>
              </div>
            )}

            {messages.map((message) => (
              <div
                key={message.id}
                className={`assistant-message-row message-${message.role}`}
              >
                <span className={`message-avatar ${message.role === 'user' ? 'user-avatar' : ''}`}>
                  {message.role === 'user' ? <Mic aria-hidden="true" /> : <Bot aria-hidden="true" />}
                </span>
                <div className="message-stack">
                  <div className={`assistant-message-bubble ${message.role === 'user' ? 'is-user' : ''}`}>
                    {message.role === 'assistant' && message.markdown ? (
                      <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeHighlight]}>
                        {message.markdown}
                      </ReactMarkdown>
                    ) : (
                      message.content
                    )}
                  </div>
                  <div className="message-meta">
                    <span>{message.role === 'user' ? 'YOU' : 'ASSISTANT'}</span>
                    {message.detected_language && <span>{message.detected_language}</span>}
                    <time>{formatTime(message.timestamp)}</time>
                  </div>
                </div>
              </div>
            ))}
            <div ref={transcriptEndRef} />

            {showOnboard && (
              <div className="assistant-prompt-shelf">
                <span className="prompt-shelf-label">QUICK START</span>
                <div>
                  {PROMPT_SHELF.map((prompt) => (
                    <button
                      key={prompt.label}
                      type="button"
                      onClick={() => handlePromptClick(prompt.message)}
                    >
                      <Sparkles aria-hidden="true" />
                      {prompt.label}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {error && (
            <div className="assistant-error" role="alert">
              <AlertCircle aria-hidden="true" />
              <span>{error}</span>
              <button type="button" className="caption-stop" onClick={handleRetry} aria-label="Retry">
                <RefreshCw aria-hidden="true" />
              </button>
            </div>
          )}

          <div className="assistant-input-footer">
            <span className="composer-mode-icon">
              {mode === 'voice' ? <Mic aria-hidden="true" /> : <CornerDownLeft aria-hidden="true" />}
            </span>
            <input
              type="text"
              value={textInput}
              onChange={(event) => setTextInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault();
                  submitText();
                }
              }}
              placeholder={
                mode === 'voice'
                  ? 'Switch to text mode, or hold the mic to speak…'
                  : 'Ask about a scan, request findings, or launch an assessment…'
              }
              aria-label="Assistant text input"
            />
            <button
              type="button"
              className="composer-send"
              onClick={submitText}
              disabled={!textInput.trim() || voiceState === 'processing' || voiceState === 'speaking'}
            >
              Send <ArrowRight aria-hidden="true" />
            </button>
          </div>
          <div className="assistant-composer-foot">
            <span>Enter to send · Shift+Enter for newline</span>
            <span>{capabilities?.analysis ?? 'Evidence-based assistant'} · {ttsProviderTag}</span>
          </div>
        </div>
      </div>
    </section>
  );
};

export default AssistantHero;
