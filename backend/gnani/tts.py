import asyncio
import re
from typing import Optional, Dict, Any, AsyncIterator, List
import httpx
from backend.core.config import settings


class GnaniTTSService:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else settings.gnani_api_key
        self.endpoint_url = settings.gnani_tts_url
        self.model = settings.gnani_tts_model
        self.voice = settings.gnani_tts_voice
        self.language = settings.gnani_tts_language

    def is_configured(self) -> bool:
        """Returns True if a Gnani API key has been provided in environment."""
        return bool(self.api_key and self.api_key.strip())

    def synthesize_speech(self, text: str, voice: Optional[str] = None, speed: float = 1.0) -> Dict[str, Any]:
        """
        Synthesizes text into speech using official Gnani Timbre TTS REST API:
        - Endpoint: https://api.vachana.ai/api/v1/tts/inference
        - Method: POST
        - Header: X-API-Key-ID: <api_key>
        - Payload: { text, voice, model, language, speed, audio_config }
        - Response: Binary audio/wav data on success
        """
        if not self.is_configured():
            return {
                "success": False,
                "error": "GNANI_API_KEY is not configured.",
                "audio_bytes": None,
                "content_type": None
            }

        headers = {
            "Content-Type": "application/json",
            "X-API-Key-ID": self.api_key
        }

        payload = {
            "text": text,
            "voice": voice or self.voice,
            "model": self.model,
            "language": self.language,
            "speed": speed,
            "audio_config": {
                "sample_rate": 24000,
                "num_channels": 1,
                "sample_width": 2,
                "encoding": "linear_pcm",
                "container": "wav"
            }
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.post(
                    self.endpoint_url,
                    headers=headers,
                    json=payload
                )

                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "audio/wav").split(";", 1)[0].strip().lower()
                    if not (content_type.startswith("audio/") or content_type == "application/octet-stream"):
                        return {
                            "success": False,
                            "error": "Gnani TTS returned a non-audio response.",
                            "status_code": 502,
                            "audio_bytes": None,
                            "content_type": None,
                        }
                    if not response.content:
                        return {
                            "success": False,
                            "error": "Gnani TTS returned an empty audio response.",
                            "status_code": 502,
                            "audio_bytes": None,
                            "content_type": None,
                        }
                    return {
                        "success": True,
                        "audio_bytes": response.content,
                        "content_type": content_type,
                        "error": None
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Gnani TTS API returned HTTP {response.status_code}.",
                        "status_code": response.status_code,
                        "audio_bytes": None,
                        "content_type": None
                    }
        except Exception:
            return {
                "success": False,
                "error": "Gnani TTS request failed. Check network access and backend logs.",
                "audio_bytes": None,
                "content_type": None
            }

    # ------------------------------------------------------------------
    # Chunked synthesis (for streaming TTS endpoint)
    # ------------------------------------------------------------------
    @staticmethod
    def split_sentences(text: str, max_chars: int = 220) -> List[str]:
        """Split ``text`` into TTS-friendly chunks of at most ``max_chars``.

        Strategy (in order):
          1. Split on sentence-ending punctuation (. ! ?) followed by whitespace.
          2. If a piece still exceeds ``max_chars``, split on commas.
          3. If a comma-segment still exceeds ``max_chars``, hard-wrap at the
             boundary.

        Whitespace is normalized to single spaces before splitting.
        """
        if not text:
            return []
        normalized = re.sub(r"\s+", " ", text).strip()
        if not normalized:
            return []

        def _hard_wrap(s: str) -> List[str]:
            return [s[i:i + max_chars] for i in range(0, len(s), max_chars)]

        def _greedy_merge(parts: List[str]) -> List[str]:
            out: List[str] = []
            buf = ""
            for p in parts:
                if not buf:
                    candidate = p
                else:
                    candidate = buf + ", " + p
                if len(candidate) <= max_chars:
                    buf = candidate
                else:
                    if buf:
                        out.append(buf)
                        buf = ""
                    if len(p) <= max_chars:
                        buf = p
                    else:
                        out.extend(_hard_wrap(p))
            if buf:
                out.append(buf)
            return out

        chunks: List[str] = []
        for sentence in re.split(r"(?<=[.!?])\s+", normalized):
            sentence = sentence.strip()
            if not sentence:
                continue
            if len(sentence) <= max_chars:
                chunks.append(sentence)
                continue
            comma_parts = re.split(r",\s+", sentence)
            chunks.extend(_greedy_merge(comma_parts))
        return chunks

    async def synthesize_chunk(
        self,
        text: str,
        voice: Optional[str] = None,
        speed: float = 1.0,
    ) -> Dict[str, Any]:
        """Synthesize a single short chunk via Gnani Timbre using an async
        httpx client. Retries up to 2 additional times with exponential
        backoff (0.4s, 0.8s) on transport or HTTP errors.
        """
        if not self.is_configured():
            return {
                "success": False,
                "error": "GNANI_API_KEY is not configured.",
                "audio_bytes": None,
                "content_type": None,
            }

        headers = {
            "Content-Type": "application/json",
            "X-API-Key-ID": self.api_key,
        }
        payload = {
            "text": text,
            "voice": voice or self.voice,
            "model": self.model,
            "language": self.language,
            "speed": speed,
            "audio_config": {
                "sample_rate": 24000,
                "num_channels": 1,
                "sample_width": 2,
                "encoding": "linear_pcm",
                "container": "wav",
            },
        }

        last_err: Optional[str] = None
        for attempt in range(3):  # 1 initial + 2 retries
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    response = await client.post(
                        self.endpoint_url,
                        headers=headers,
                        json=payload,
                    )
                if response.status_code == 200:
                    content_type = (
                        response.headers.get("content-type", "audio/wav")
                        .split(";", 1)[0].strip().lower()
                    )
                    if not (
                        content_type.startswith("audio/")
                        or content_type == "application/octet-stream"
                    ):
                        return {
                            "success": False,
                            "error": "Gnani TTS returned a non-audio response.",
                            "status_code": 502,
                            "audio_bytes": None,
                            "content_type": None,
                        }
                    if not response.content:
                        return {
                            "success": False,
                            "error": "Gnani TTS returned an empty audio response.",
                            "status_code": 502,
                            "audio_bytes": None,
                            "content_type": None,
                        }
                    return {
                        "success": True,
                        "audio_bytes": response.content,
                        "content_type": content_type,
                        "error": None,
                    }
                else:
                    last_err = f"Gnani TTS API returned HTTP {response.status_code}."
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc) or "Gnani TTS request failed."
            if attempt < 2:
                await asyncio.sleep(0.4 * (2 ** attempt))  # 0.4s, 0.8s
        return {
            "success": False,
            "error": last_err or "Gnani TTS request failed.",
            "audio_bytes": None,
            "content_type": None,
        }

    async def stream_tts(
        self,
        text: str,
        voice: Optional[str] = None,
        speed: float = 1.0,
    ) -> AsyncIterator[bytes]:
        """Async generator yielding WAV audio chunks for the input text.

        Splits the text into sentences, synthesizes up to 3 chunks concurrently
        via ``asyncio.Semaphore(3)``, and yields each WAV chunk as soon as it
        completes (via ``asyncio.as_completed``). This minimizes time-to-first-
        audio compared to monolithic synthesis.

        Failed chunks are silently skipped - the caller receives a partial
        stream when individual chunks fail (e.g. transient network errors).
        """
        if not self.is_configured():
            return

        chunks = self.split_sentences(text)
        if not chunks:
            return

        sem = asyncio.Semaphore(3)

        async def _synth(idx: int, chunk: str):
            async with sem:
                result = await self.synthesize_chunk(chunk, voice=voice, speed=speed)
                return idx, result

        tasks = [asyncio.create_task(_synth(i, c)) for i, c in enumerate(chunks)]
        results_map = {}
        next_to_yield = 0
        try:
            for completed in asyncio.as_completed(tasks):
                idx, result = await completed
                results_map[idx] = result
                while next_to_yield in results_map:
                    res = results_map.pop(next_to_yield)
                    if res.get("success"):
                        yield res["audio_bytes"]
                    next_to_yield += 1
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
