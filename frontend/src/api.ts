import type { Scan, Asset, Finding, GraphData } from './types';

const BASE_URL = '/api';

export interface AppCapabilities {
  stt: { configured: boolean; model: string };
  tts: { configured: boolean; model: string; voice: string };
  analysis: string;
  domain_auth_mode: 'demo_attestation' | 'dns_txt';
  domain_auth_label: string;
}

export interface AuthUser { id: number; email: string }
export interface AssistantHistoryMessage {
  role: 'user' | 'assistant';
  content: string;
}

let csrfToken: string | null = null;
let csrfRequest: Promise<string> | null = null;

async function ensureCsrfToken(): Promise<string> {
  if (csrfToken) return csrfToken;
  if (!csrfRequest) {
    csrfRequest = fetch(`${BASE_URL}/auth/csrf`, { credentials: 'include' })
      .then(async (response) => {
        if (!response.ok) throw new Error('Could not initialize a secure session.');
        const payload = await response.json() as { csrf_token: string };
        csrfToken = payload.csrf_token;
        return payload.csrf_token;
      })
      .finally(() => { csrfRequest = null; });
  }
  return csrfRequest;
}

async function apiFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    headers.set('X-CSRF-Token', await ensureCsrfToken());
  }
  const response = await fetch(input, { ...init, headers, credentials: 'include' });
  const path = input.replace(BASE_URL, '');
  if (response.status === 401 && !path.startsWith('/auth/')) {
    window.dispatchEvent(new Event('exposuregraph:unauthorized'));
  }
  return response;
}

export async function fetchCurrentUser(): Promise<AuthUser | null> {
  const res = await apiFetch(`${BASE_URL}/auth/me`);
  if (res.status === 401) return null;
  if (!res.ok) throw new Error('Could not verify the current session.');
  return res.json();
}

export async function loginUser(email: string, password: string): Promise<AuthUser> {
  await ensureCsrfToken();
  const res = await apiFetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || 'Sign in failed.');
  }
  return res.json();
}

export async function logoutUser(): Promise<void> {
  const res = await apiFetch(`${BASE_URL}/auth/logout`, { method: 'POST' });
  if (!res.ok) throw new Error('Sign out failed.');
  csrfToken = null;
}

export async function fetchCapabilities(): Promise<AppCapabilities> {
  const res = await apiFetch(`${BASE_URL}/capabilities`);
  if (!res.ok) throw new Error('Failed to fetch integration status');
  return res.json();
}

export async function fetchScans(): Promise<Scan[]> {
  const res = await apiFetch(`${BASE_URL}/scans`);
  if (!res.ok) throw new Error('Failed to fetch scans');
  return res.json();
}

export async function fetchScan(id: number): Promise<Scan> {
  const res = await apiFetch(`${BASE_URL}/scans/${id}`);
  if (!res.ok) throw new Error('Failed to fetch scan');
  return res.json();
}

export async function requestManualAttestation(domain: string): Promise<{ authorization_token: string; domain: string }> {
  const res = await apiFetch(`${BASE_URL}/auth/attest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, attestation_confirmed: true }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || 'Attestation failed');
  }
  return res.json();
}

export async function startScan(domain: string, authorized: boolean, authorizationToken?: string): Promise<Scan> {
  let token = authorizationToken;

  if (!token && authorized) {
    const attestRes = await requestManualAttestation(domain);
    token = attestRes.authorization_token;
  }

  const res = await apiFetch(`${BASE_URL}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, authorized, authorization_token: token }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || 'Failed to start scan');
  }
  return res.json();
}

export async function fetchScanAssets(scanId: number): Promise<Asset[]> {
  const res = await apiFetch(`${BASE_URL}/scans/${scanId}/assets`);
  if (!res.ok) throw new Error('Failed to fetch assets');
  return res.json();
}

export async function fetchScanFindings(scanId: number, severity?: string): Promise<Finding[]> {
  const url = severity ? `${BASE_URL}/scans/${scanId}/findings?severity=${severity}` : `${BASE_URL}/scans/${scanId}/findings`;
  const res = await apiFetch(url);
  if (!res.ok) throw new Error('Failed to fetch findings');
  return res.json();
}

export async function fetchScanGraph(scanId: number): Promise<GraphData> {
  const res = await apiFetch(`${BASE_URL}/scans/${scanId}/graph`);
  if (!res.ok) throw new Error('Failed to fetch graph');
  return res.json();
}

export async function transcribeVoice(file: Blob, filename?: string): Promise<{
  success: boolean;
  transcript: string;
  detected_language?: string;
  parsed_domain?: string;
  error?: string;
}> {
  const formData = new FormData();
  
  let uploadFilename = filename;
  if (!uploadFilename) {
    if (file.type.includes('wav')) {
      uploadFilename = 'voice_command.wav';
    } else if (file.type.includes('webm')) {
      uploadFilename = 'voice_command.webm';
    } else if (file.type.includes('ogg')) {
      uploadFilename = 'voice_command.ogg';
    } else if (file.type.includes('mp4') || file.type.includes('aac')) {
      uploadFilename = 'voice_command.m4a';
    } else {
      uploadFilename = 'voice_command.audio';
    }
  }

  formData.append('file', file, uploadFilename);

  const res = await apiFetch(`${BASE_URL}/voice/transcribe`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Voice transcription failed');
  }
  return res.json();
}

export async function chatAssistant(
  message: string,
  currentState: string,
  currentDomain?: string,
  scanId?: number,
  conversationHistory: AssistantHistoryMessage[] = [],
): Promise<{
  assistant_reply: string;
  next_state: string;
  domain?: string;
  authorized: boolean;
  can_launch: boolean;
  authorization_token?: string;
}> {
  const res = await apiFetch(`${BASE_URL}/voice/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message,
      current_state: currentState,
      current_domain: currentDomain || null,
      scan_id: scanId || null,
      conversation_history: conversationHistory,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to communicate with assistant');
  }
  return res.json();
}

export async function fetchGnaniTTSAudio(text: string, voice = 'Nalini', speed = 1.0): Promise<Blob> {
  const res = await apiFetch(`${BASE_URL}/voice/tts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, voice, speed }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Gnani TTS failed with status ${res.status}`);
  }
  return res.blob();
}

export interface DomainChallenge {
  id: number;
  domain: string;
  record_name: string;
  record_value: string;
  expires_at: string;
}

export async function createDomainChallenge(domain: string): Promise<DomainChallenge> {
  const res = await apiFetch(`${BASE_URL}/domains/challenges`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || 'Could not create a DNS verification challenge.');
  }
  return res.json();
}

export async function verifyDomainChallenge(challengeId: number): Promise<{ verified: boolean; domain: string; authorization_token: string }> {
  const res = await apiFetch(`${BASE_URL}/domains/challenges/${challengeId}/verify`, { method: 'POST' });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || 'DNS verification failed.');
  }
  return res.json();
}

export async function authorizeVerifiedDomain(domain: string): Promise<{ authorization_token: string; domain: string }> {
  const res = await apiFetch(`${BASE_URL}/domains/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || 'Domain ownership is not currently verified.');
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Streaming voice APIs (SSE token stream + chunked TTS audio).
// Both fall back to the non-streaming equivalents when the backend
// does not advertise a streaming endpoint or returns a non-OK response.
// ---------------------------------------------------------------------------

export interface AssistantStreamResult {
  next_state: string;
  authorized: boolean;
  can_launch: boolean;
  domain?: string;
  authorization_token?: string;
  detected_language?: string;
  markdown?: string;
  reply?: string;
}

/** Coerce a non-streaming {@link chatAssistant} result into the streaming shape. */
async function fallbackAssistantResult(
  message: string,
  currentState: string,
  scanId: number | undefined,
  conversationHistory: AssistantHistoryMessage[],
): Promise<AssistantStreamResult> {
  const result = await chatAssistant(message, currentState, undefined, scanId, conversationHistory);
  return {
    next_state: result.next_state,
    authorized: result.authorized,
    can_launch: result.can_launch,
    domain: result.domain,
    authorization_token: result.authorization_token,
    markdown: result.assistant_reply,
    reply: result.assistant_reply,
  };
}

/**
 * Stream assistant chat tokens from `/api/voice/chat/stream` (Server-Sent
 * Events). Each `data: {...}` line whose `type === 'token'` is delivered to
 * `onToken` as it arrives so the UI can reveal the reply word-by-word. A
 * terminating `done` event carries the final conversation-state payload.
 *
 * Falls back to {@link chatAssistant} if the server doesn't support
 * streaming, the request is aborted by the caller, or the SSE stream is
 * malformed.
 */
export async function streamAssistantChat(
  message: string,
  currentState: string,
  scanId?: number,
  currentDomain?: string,
  detectedLanguage?: string,
  onToken?: (token: string, replace?: boolean) => void,
  signal?: AbortSignal,
  conversationHistory: AssistantHistoryMessage[] = [],
): Promise<AssistantStreamResult> {
  const csrf = await ensureCsrfToken();

  let response: Response;
  try {
    response = await fetch(`${BASE_URL}/voice/chat/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
        'X-CSRF-Token': csrf,
      },
      credentials: 'include',
      body: JSON.stringify({
        message,
        current_state: currentState,
        current_domain: currentDomain ?? null,
        scan_id: scanId ?? null,
        detected_language: detectedLanguage ?? null,
        conversation_history: conversationHistory,
      }),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw err;
    }
    return fallbackAssistantResult(message, currentState, scanId, conversationHistory);
  }

  if (!response.ok || !response.body) {
    return fallbackAssistantResult(message, currentState, scanId, conversationHistory);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let pendingEvent = '';
  let assembled = '';
  let donePayload: AssistantStreamResult | null = null;

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() ?? '';

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) {
          pendingEvent = '';
          continue;
        }
        if (line.startsWith('event:')) {
          pendingEvent = line.slice(6).trim();
          continue;
        }
        if (!line.startsWith('data:')) continue;

        const payload = line.slice(5).trim();
        if (!payload) continue;

        let event: Record<string, unknown>;
        try {
          event = JSON.parse(payload) as Record<string, unknown>;
        } catch {
          continue;
        }

        const type = (event.type as string | undefined) ?? pendingEvent;
        if (type === 'token' && typeof event.text === 'string') {
          const replace = event.replace === true;
          assembled = replace ? event.text : assembled + event.text;
          onToken?.(event.text, replace);
        } else if (type === 'done' || type === 'complete') {
          donePayload = {
            next_state: (event.next_state as string) ?? currentState,
            authorized: Boolean(event.authorized),
            can_launch: Boolean(event.can_launch),
            domain: event.domain as string | undefined,
            authorization_token: event.authorization_token as string | undefined,
            detected_language: event.detected_language as string | undefined,
            markdown: (event.markdown as string) ?? (event.reply as string) ?? assembled,
            reply: (event.reply as string) ?? assembled,
          };
        } else if (type === 'error') {
          // Server reported a mid-stream error: fall back.
          return fallbackAssistantResult(message, currentState, scanId, conversationHistory);
        }
      }
    }
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw err;
    }
    if (assembled) {
      // We did receive some tokens; synthesize a minimal done payload so
      // the caller can keep the partial reply instead of dropping it.
      return {
        next_state: currentState,
        authorized: false,
        can_launch: false,
        markdown: assembled,
        reply: assembled,
      };
    }
    return fallbackAssistantResult(message, currentState, scanId, conversationHistory);
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
  }

  if (donePayload) return donePayload;

  // Stream ended without an explicit done event. Use whatever we assembled.
  if (assembled) {
    return {
      next_state: currentState,
      authorized: false,
      can_launch: false,
      markdown: assembled,
      reply: assembled,
    };
  }

  return fallbackAssistantResult(message, currentState, scanId, conversationHistory);
}

/**
 * Stream chunked TTS audio bytes from `/api/voice/tts/stream`. Yields
 * raw `ArrayBuffer` chunks as they arrive so the caller can decode and
 * schedule them on an `AudioBufferSourceNode` for low-latency playback.
 *
 * Resolves with an empty generator when the endpoint is unavailable.
 */
export async function* streamTTS(
  text: string,
  voice = 'Nalini',
  speed = 1.0,
  signal?: AbortSignal,
): AsyncGenerator<ArrayBuffer, void, void> {
  const csrf = await ensureCsrfToken();

  let response: Response;
  try {
    response = await fetch(`${BASE_URL}/voice/tts/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
      },
      credentials: 'include',
      body: JSON.stringify({ text, voice, speed }),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err;
    return;
  }

  if (!response.ok || !response.body) return;

  const reader = response.body.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        yield value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
      }
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
  }
}
