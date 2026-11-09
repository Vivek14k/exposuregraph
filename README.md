# ExposureGraph

**ExposureGraph** is a cybersecurity SaaS MVP designed for individual developers and small startups to discover, map, and evaluate their external attack surfaces and security exposure.

---

## 🎯 Overview

Modern cloud-native developers and startups often struggle with visibility across fragmented external digital assets, including domains, subdomains, DNS records, network endpoints, and exposed services.

ExposureGraph provides a graph-driven approach to external attack surface management through asset discovery, security assessment, evidence-backed findings, and risk prioritization.

### Core Capabilities

- **Discover Attack Surfaces:** Perform bounded discovery of authorized domains, common subdomains, DNS records, and supported HTTP/TLS endpoints.
- **Model Relationships (Graph):** Visualize discovered assets and their recorded relationships to understand the external attack surface and potential exposure paths.
- **Prioritize Risk:** Evaluate detected security issues using a deterministic risk engine and provide actionable remediation guidance for lean teams.
- **AI-Assisted Security Interaction:** Ask questions about assessment results through text and voice-based assistant interactions.
- **Generate Reports:** Review and export reports based on saved assessment data.

---

## 🤖 Gnani AI Integration

ExposureGraph integrates Gnani AI speech technologies to enable voice-based interaction with its security assessment assistant.

### Gnani AI Models and APIs

- **Prisma — Speech-to-Text (STT):** Converts spoken user queries into text for processing by the assistant.
- **Timbre — Text-to-Speech (TTS):** Converts generated assistant responses into spoken audio.

### AI Assistant Architecture

The application uses separate components for natural-language reasoning, speech recognition, and speech generation.

| Technology | Responsibility |
|---|---|
| Gnani Prisma | Speech recognition and transcription |
| Gnani Timbre | Speech generation and audio responses |
| Gemini 2.5 Flash | Natural-language reasoning and function calling |
| FastAPI Backend | Connects assistant interactions to assessment data and application functions |

The assistant uses actual assessment data to answer security-related questions. Its function-calling tools provide access to:

- `get_scan_summary`
- `list_findings`
- `get_finding_detail`
- `list_assets`
- `compare_scans`

The assistant is designed to ground its responses in retrieved assessment evidence rather than independently inventing scan results.

Gemini and Gnani AI serve different purposes:

- Gemini handles natural-language reasoning.
- Gnani Prisma handles speech recognition.
- Gnani Timbre handles speech generation.

The language model does not issue domain authorization tokens or independently modify deterministic risk scores.

---

## 📁 Repository Structure

```text
exposuregraph/
├── backend/
│   ├── api/              # API routing, endpoints, and schemas
│   ├── app/              # Application entrypoint and lifecycle
│   ├── core/             # Configuration, authentication, security
│   ├── database/         # Database models and persistence
│   ├── discovery/        # External asset discovery
│   ├── gnani/            # AI assistant, LLM, STT, and TTS
│   ├── graph/            # Graph-based exposure mapping
│   ├── migrations/       # Database migrations
│   ├── risk_engine/      # Risk scoring and evaluation
│   ├── scanner/          # Security checks and scan orchestration
│   ├── Dockerfile
│   ├── requirements.txt
│   └── requirements-dev.txt
├── frontend/
│   ├── src/
│   │   ├── components/   # Application UI components
│   │   ├── utils/        # Frontend utilities
│   │   ├── App.tsx
│   │   └── api.ts
│   ├── package.json
│   └── vite.config.ts
├── .env.example          # Environment-variable template
├── .gitignore            # Excludes secrets and local data
├── alembic.ini           # Database migration configuration
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python compatible with the packages in `backend/requirements.txt`
- Node.js and npm
- Git

### Setup

From the project root, create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install backend dependencies:

```powershell
python -m pip install -r backend/requirements.txt
```

Create a private local environment file:

```powershell
Copy-Item .env.example .env
```

Install frontend dependencies:

```powershell
cd frontend
npm ci
```

Edit the local `.env` file with the required configuration and provider credentials.

**Never commit `.env` or publish API keys, passwords, tokens, or other credentials.**

---

## 🔒 Security & Best Practices

ExposureGraph incorporates security controls intended to protect assessment scope, user data, and scan execution.

### Application Security

- Domain authorization is required before assessments can proceed.
- Authentication uses database-backed sessions, per-user scan ownership, CSRF tokens, and password hashing.
- Public account registration is disabled. Accounts are created through the administrator CLI.
- Production configuration requires DNS TXT domain verification.
- Local demo mode uses user attestation and does not independently prove domain ownership.

### Scanner Safety

Scanner probes are limited to ports:

- 80
- 443
- 8080
- 8443

Additional safeguards include:

- Redirects are not followed.
- Non-public IP addresses are rejected.
- HTTP connections are pinned to validated IP addresses.
- TLS certificates are verified.
- Response bodies and scan execution time are bounded.

Assessments must only target domains and assets owned by the user or for which explicit authorization has been obtained.

### Credential Security

- Never commit `.env` files or actual API credentials.
- Use `.env.example` only for safe configuration examples.
- Keep database files, local scan records, and private reports out of source control.
- If a real API key was ever committed or shared publicly, revoke it and generate a replacement. Removing it from the latest version does not remove it from Git history.

---

## ⚙️ Runtime Modes and Limits

### AI Assistant

Assistant responses are generated using **Gemini 2.5 Flash** through the `google-genai` library.

The assistant:

- Uses function-calling tools to retrieve actual scan information.
- Maintains a bounded recent conversation history for follow-up context.
- Mirrors detected speech language without carrying a previous voice locale into typed messages.
- Uses evidence-grounded responses.
- Falls back to deterministic replies if Gemini is unavailable.

### Gnani Speech Integration

Gnani AI services provide speech capabilities:

- `GNANI_API_KEY` enables Prisma speech recognition and Timbre speech output.
- `GNANI_STT_URL` configures the speech-to-text endpoint.
- `GNANI_TTS_URL` configures the text-to-speech endpoint.

Gemini and Gnani keys serve different roles.

| Configuration | Purpose |
|---|---|
| `GEMINI_API_KEY` | Natural-language reasoning |
| `GNANI_API_KEY` | Speech recognition and speech generation |

Without the Gemini API key, text responses use the deterministic fallback.

### Scanner Limitations

The scanner performs best-effort DNS discovery for a bounded list of common hostnames and checks supported HTTP/TLS behavior.

Its coverage is not equivalent to a penetration test.

- A timeout does not establish that a vulnerability exists.
- An unavailable host does not automatically indicate a security issue.
- Findings are based on supported checks and recorded evidence.
- Reports contain only saved scan data.

### Database and Worker Limitations

SQLite is intended for local development.

Production deployments should use PostgreSQL and a single database-locked scan worker.

Scan execution and interruption recovery are designed for a single active worker. Running multiple scan workers is not supported by the current design.

---

## 🖥️ Run Locally

### 1. Configure the Environment

From the project root:

```powershell
Copy-Item .env.example .env
```

Configure the required local settings and provider credentials.

For local demonstration:

```env
DOMAIN_AUTH_MODE=demo_attestation
```

For production domain ownership verification:

```env
DOMAIN_AUTH_MODE=dns_txt
```

Use a securely generated `SESSION_SECRET` for your local configuration.

### 2. Initialize the Database

Activate the Python virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Run database migrations:

```powershell
python -m alembic upgrade head
```

The application does not automatically create database tables.

Existing SQLite data is preserved by migrations. Legacy scans remain unowned until explicitly claimed.

### 3. Create an Administrator Account

Run:

```powershell
python -m backend.cli create-user analyst@example.com
```

Replace the example email with the account you want to create.

The CLI prompts for a password without exposing it in the command line.

### 4. Start the Backend

Run:

```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Backend health check:

`http://127.0.0.1:8000/health`

API documentation is enabled only when `DEBUG=true`.

### 5. Start the Frontend

Open another PowerShell terminal:

```powershell
cd frontend
npm run dev -- --host 127.0.0.1
```

Open:

`http://127.0.0.1:5173`

Sign in using the account created through the administrator CLI.

Select Text mode if microphone permission or browser audio support is unavailable.

The local Vite server proxies `/api` requests to:

`http://127.0.0.1:8000`

### 6. Configure AI Providers

Configure the following variables in `.env`:

```env
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-flash

GNANI_API_KEY=
GNANI_STT_URL=
GNANI_TTS_URL=
```

Use your own valid provider credentials and the appropriate API endpoint configuration.

The assistant footer displays the active reply and speech providers.

---

## 🆕 AI Assistant and Voice Integration Upgrade

This version introduces a Gemini-powered reasoning layer, streaming chat, and an upgraded voice interaction experience.

### Backend Changes

- **`backend/gnani/llm.py`** — Gemini client, evidence-grounded system prompt, five function-calling tools, asynchronous streaming generator, retries, and Pydantic guardrails.
- **`backend/gnani/assistant.py`** — `answer_scan_question()` uses the LLM, while the original keyword-based implementation remains available as a deterministic fallback. The authorization state machine and `AuthorizationTokenManager` remain separate.
- **`backend/gnani/composer.py`** — Fixed class-level mutable state by moving recent-hash and caveat tracking to instance-level state.
- **`backend/gnani/tts.py`** — Added sentence splitting, chunk synthesis, retries, and parallel chunked TTS streaming using `asyncio.Semaphore(3)`.
- **`backend/gnani/stt.py`** — Added two retries with exponential backoff.
- **`backend/api/routes.py`** — Added `POST /api/voice/chat/stream` for Server-Sent Events and `POST /api/voice/tts/stream` for chunked WAV responses. Existing endpoints are preserved.
- **`backend/api/schemas.py`** — Increased `TTSRequest.text` limit from 2,000 to 6,000 characters and added `detected_language` to `AssistantChatRequest`.
- **`backend/core/config.py`** — Added Gemini API key and model configuration.
- **`backend/requirements.txt`** — Added `google-genai>=1.0.0`.

### Frontend Changes

The frontend was reconstructed and upgraded to support the assistant and voice workflow.

- **`src/types.ts`** — Reconstructed frontend type definitions.
- **`src/components/AssistantHero.tsx`** — Voice and chat interface with MediaRecorder push-to-talk, six voice states, streaming Markdown messages, audio-reactive visualization, interruption handling, local persistence, and voice/text mode switching.
- **`src/components/AuthGate.tsx`** — Authentication interface.
- **`src/components/NewScanModal.tsx`** — New assessment interface.
- **`src/components/ExposureGraphView.tsx`** — Attack graph visualization.
- **`src/components/AssetInventory.tsx`** — Asset inventory interface.
- **`src/components/FindingsList.tsx`** — Security findings interface.
- **`src/components/AssessmentCoverage.tsx`** — Assessment coverage interface.
- **`src/utils/navigationIntent.ts`** — Parses navigation intents from assistant responses.
- **`src/api.ts`** — Added `streamAssistantChat()` for SSE responses and `streamTTS()` for chunked audio generation.
- **`index.html`** — Updated application title, theme color, preconnect, and font preload configuration.
- **`package.json`** — Added `react-markdown`, `remark-gfm`, `rehype-highlight`, and `highlight.js`.

### Additional Environment Variables

```env
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-flash

GNANI_API_KEY=
```

Gemini is used for natural-language reasoning. Gnani Prisma and Timbre provide speech recognition and speech generation.

---

## ☁️ Production Deployment

Deployment manifests and a production Compose file are not included in this repository.

Before deploying, configure:

- A stable, randomly generated `SESSION_SECRET` of at least 32 characters.
- HTTPS with `COOKIE_SECURE=true`.
- `DOMAIN_AUTH_MODE=dns_txt`.
- A production database such as PostgreSQL.
- Narrowly scoped CORS origins.
- A TLS-terminating reverse proxy.
- Private database and API ports.
- A single scan worker.

Back up the database and review migrations before applying them.

The initial migration preserves legacy scans as unowned. Use `--claim-legacy-scans` only when assigning every legacy scan to one account is intentional.

The current implementation is designed around a single active scan worker. Do not scale the worker beyond one instance without redesigning and validating scan coordination.

---

## 🧪 Verification

The following commands can be used to perform local verification.

### Backend Python Syntax

From the project root:

```powershell
python -m compileall -q backend
```

### Frontend Dependency Installation

From the frontend directory:

```powershell
npm ci
```

### Frontend Lint

```powershell
npm run lint
```

### Frontend Production Build

```powershell
npm run build
```

### Production Dependency Audit

```powershell
npm audit --omit=dev --audit-level=high
```

There is currently no automated test suite or CI workflow included in this repository.

The commands above validate Python syntax, frontend linting and build output, and production frontend dependencies. They do not establish complete application correctness, perform a live security assessment, or deploy the application.

---

## 🎥 Project Demonstration

A public demonstration video of ExposureGraph will be published as part of the Great Indian AI Internship Challenge submission.

The demonstration is intended to cover:

- Authorized domain assessment workflow.
- External asset discovery.
- Security findings and risk prioritization.
- Attack graph visualization.
- Gnani AI-powered voice interaction.
- Evidence-grounded assistant responses.
- Assessment reports.

---

## 📄 License

**Proprietary / In Development. All rights reserved.**

This project is currently under development. No permission to redistribute, modify, or commercially use the source code is granted unless separately authorized.
