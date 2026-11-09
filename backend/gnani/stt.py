
import re
import time
from typing import Dict, Any, Optional
import httpx
from backend.core.config import settings


def detect_audio_format(audio_bytes: bytes, incoming_filename: str = "") -> tuple[str, str]:
    """
    Detects true audio format from file magic bytes and returns (actual_mime_type, normalized_filename).
    Prevents mismatched headers such as labeling WebM bytes as audio/wav.
    """
    if len(audio_bytes) >= 4 and audio_bytes[:4] == b"RIFF" and len(audio_bytes) >= 12 and audio_bytes[8:12] == b"WAVE":
        return "audio/wav", "recording.wav"
    elif len(audio_bytes) >= 4 and audio_bytes[:4] == b"\x1a\x45\xdf\xa3":
        # EBML container (WebM / Matroska)
        return "audio/webm", "recording.webm"
    elif len(audio_bytes) >= 4 and audio_bytes[:4] == b"OggS":
        return "audio/ogg", "recording.ogg"
    elif len(audio_bytes) >= 4 and audio_bytes[:4] == b"fLaC":
        return "audio/flac", "recording.flac"
    elif len(audio_bytes) >= 3 and (audio_bytes[:3] == b"ID3" or audio_bytes[:2] == b"\xff\xfb" or audio_bytes[:2] == b"\xff\xf3"):
        return "audio/mpeg", "recording.mp3"
    elif len(audio_bytes) >= 8 and audio_bytes[4:8] == b"ftyp":
        return "audio/mp4", "recording.m4a"

    # Fallback to incoming filename extension if recognized
    ext = incoming_filename.lower().split(".")[-1] if "." in incoming_filename else ""
    if ext == "wav":
        return "audio/wav", incoming_filename
    elif ext == "webm":
        return "audio/webm", incoming_filename
    elif ext == "ogg":
        return "audio/ogg", incoming_filename
    elif ext == "mp3":
        return "audio/mpeg", incoming_filename
    elif ext in ("m4a", "aac", "mp4"):
        return "audio/mp4", incoming_filename

    # Default fallback
    return "audio/wav", "recording.wav"


class GnaniSTTService:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else settings.gnani_api_key
        self.endpoint_url = settings.gnani_stt_url
        self.model = settings.gnani_model
        self.language_code = settings.gnani_language_code

    def is_configured(self) -> bool:
        """Returns True if a Gnani API key has been provided via environment variable."""
        return bool(self.api_key and self.api_key.strip())

    def transcribe_audio(self, audio_bytes: bytes, filename: str = "voice_command.wav") -> Dict[str, Any]:
        """
        Transcribes speech audio via Gnani.ai Prisma STT API.
        Uses the official Prisma STT REST contract:
        - URL: https://api.vachana.ai/stt/v3
        - Header: X-API-Key-ID: <api_key>
        - Method: POST multipart/form-data
        - Audio field: audio_file

        Retries up to 3 attempts total (initial + 2 retries) with exponential
        backoff (0.4s, 0.8s) on transport errors or 5xx server responses.
        4xx responses and "couldn't transcribe" successes are not retried.
        """
        if not self.is_configured():
            return {
                "success": False,
                "error": "GNANI_API_KEY is not configured in environment variables. Please provide GNANI_API_KEY in your .env file.",
                "transcript": ""
            }

        # Detect genuine audio format and enforce matching MIME type and filename
        mime_type, verified_filename = detect_audio_format(audio_bytes, filename)

        headers = {
            "X-API-Key-ID": self.api_key
        }

        data = {
            "model": self.model,
            "language_code": self.language_code,
            "format": "transcribe"
        }

        files = {
            "audio_file": (verified_filename, audio_bytes, mime_type)
        }

        last_err: Optional[str] = None
        last_status: Optional[int] = None
        for attempt in range(3):  # 1 initial + 2 retries
            try:
                with httpx.Client(timeout=15.0) as client:
                    response = client.post(
                        self.endpoint_url,
                        headers=headers,
                        data=data,
                        files=files
                    )

                if response.status_code == 200:
                    try:
                        resp_json = response.json()
                    except ValueError:
                        return {
                            "success": False,
                            "error": "Gnani STT returned an unreadable response.",
                            "transcript": "",
                        }
                    if resp_json.get("success") is False:
                        return {
                            "success": False,
                            "error": "Gnani STT could not transcribe this audio clip.",
                            "transcript": "",
                        }
                    transcript = resp_json.get("transcript", "").strip()
                    detected_lang = resp_json.get("detected_language_code", self.language_code)

                    return {
                        "success": True,
                        "transcript": transcript,
                        "detected_language": detected_lang,
                        "parsed_domain": self.extract_domain_from_command(transcript)
                    }
                else:
                    last_status = response.status_code
                    last_err = f"Gnani STT API returned HTTP {response.status_code}."
                    # Only retry on 5xx (transient). 4xx (auth/format) won't fix itself.
                    if 500 <= response.status_code < 600 and attempt < 2:
                        time.sleep(0.4 * (2 ** attempt))
                        continue
                    return {
                        "success": False,
                        "status_code": response.status_code,
                        "error": last_err,
                        "transcript": ""
                    }
            except Exception:
                last_err = "Gnani STT request failed. Check network access and backend logs."
                if attempt < 2:
                    time.sleep(0.4 * (2 ** attempt))
                    continue
                return {
                    "success": False,
                    "error": last_err,
                    "transcript": ""
                }
        # Exhausted retries
        return {
            "success": False,
            "status_code": last_status,
            "error": last_err or "Gnani STT request failed after retries.",
            "transcript": ""
        }

    @staticmethod
    def extract_domain_from_command(text: str) -> Optional[str]:
        """
        Extracts domain mentions from voice commands like:
        - "Scan domain example.com"
        - "Please check my attack surface for mycompany.io"
        - "example.org"
        """
        if not text:
            return None
            
        # Clean standard voice speech artifacts like spoken 'dot'
        cleaned = re.sub(r"\s+dot\s+", ".", text, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s+dot", ".", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"dot\s+", ".", cleaned, flags=re.IGNORECASE)
        
        # Match standard domain pattern word boundaries
        match = re.search(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b", cleaned)
        if match:
            return match.group(1).lower()
        return None
