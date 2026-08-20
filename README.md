# ThreatFusion AI
### Multi-Agent System for Explainable Phishing & Social Engineering Detection

> A production-style academic cybersecurity project demonstrating Multi-Agent AI, Retrieval-Augmented Generation (RAG), Explainable AI, and real threat intelligence integration.

---

## Project Overview

ThreatFusion AI is a web application that analyses emails for phishing and social engineering threats using **four specialised AI agents** working concurrently, followed by a transparent **Fusion Engine** that combines their signals into an evidence-backed risk verdict.

Unlike a simple spam classifier, ThreatFusion behaves like a SOC analyst team:

```
Email Input
    │
    ├──► Header/Metadata Agent   (deterministic rules)
    ├──► Content/Linguistic Agent (Gemini LLM + fallback)
    ├──► URL/Threat Intel Agent   (VirusTotal + heuristics)
    └──► Memory/RAG Agent         (ChromaDB similarity)
                │
                ▼
          Fusion Agent
     (weighted transparent scoring)
                │
                ▼
    SAFE / SUSPICIOUS / HIGH RISK / CRITICAL
    + Evidence + Explanation + Recommendations
```

---

## Key Academic Concepts Demonstrated

| Concept | Implementation |
|---|---|
| **Multi-Agent Systems** | 4 independent specialised agents run concurrently |
| **Retrieval-Augmented Generation** | ChromaDB + sentence-transformers for campaign similarity |
| **Explainable AI** | Every verdict backed by evidence, not a black-box decision |
| **LLM Engineering** | Gemini with prompt injection defence + structured JSON output |
| **Cybersecurity** | Phishing, spoofing, typosquatting, threat intelligence |
| **Software Engineering** | FastAPI + React + Docker + SQLite + pytest |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    React Frontend                    │
│         Dashboard · Analyse · History · Memory       │
└──────────────────────┬──────────────────────────────┘
                       │  HTTP/REST
┌──────────────────────▼──────────────────────────────┐
│                  FastAPI Backend                     │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │         Email Parser (Python stdlib)          │   │
│  └──────┬───────────┬──────────┬────────────────┘   │
│         │           │          │          │          │
│  ┌──────▼──┐ ┌──────▼──┐ ┌────▼────┐ ┌──▼──────┐  │
│  │ Header  │ │ Content │ │  URL    │ │ Memory  │  │
│  │ Agent   │ │ Agent   │ │ Agent   │ │ Agent   │  │
│  │(rules)  │ │(Gemini) │ │  (VT)  │ │(Chroma) │  │
│  └──────┬──┘ └──────┬──┘ └────┬────┘ └──┬──────┘  │
│         └───────────┴──────────┴─────────┘          │
│                         │                            │
│                 ┌────────▼───────┐                   │
│                 │  Fusion Agent  │                   │
│                 │ (weighted avg) │                   │
│                 └────────────────┘                   │
│                                                      │
│         SQLite (history) · ChromaDB (memory)        │
└─────────────────────────────────────────────────────┘
```

---

## Technology Stack

**Backend**
- Python 3.11, FastAPI, Pydantic v2, SQLAlchemy (async), SQLite
- LangChain, Google Gemini 1.5 Flash
- ChromaDB, sentence-transformers (`all-MiniLM-L6-v2`)
- httpx, BeautifulSoup4, tldextract, python-Levenshtein

**Frontend**
- React 18, Vite, Tailwind CSS, Recharts, React Router, Axios

**DevOps**
- Docker Compose, pytest, pytest-asyncio

---

## Installation (Windows 11 / VS Code)

### Prerequisites

```powershell
# Check Python version (must be 3.11+)
python --version

# Check Node version (must be 18+)
node --version
npm --version
```

### 1 — Clone / Extract the project

```powershell
cd C:\Projects
# If cloning from git:
# git clone <repo-url> ThreatFusion-AI
cd ThreatFusion-AI
```

### 2 — Backend setup

```powershell
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
copy .env.example .env
# Then edit .env and add your API keys (optional)
```

### 3 — Frontend setup

```powershell
cd ..\frontend

npm install

copy .env.example .env
```

---

## Environment Variables

Edit `backend/.env`:

```env
# Optional — enables AI content analysis (fallback to heuristics without it)
GEMINI_API_KEY=your_gemini_api_key_here

# Optional — enables VirusTotal URL reputation (fallback to local heuristics without it)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Server
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
FRONTEND_URL=http://localhost:5173

# Storage
CHROMA_PERSIST_DIRECTORY=./chroma_data
DATABASE_URL=sqlite+aiosqlite:///./threatfusion.db
```

> **The application works without any API keys.** All agents have fallback modes.

---

## Running Locally

### Start the Backend

```powershell
cd backend
venv\Scripts\activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend available at: `http://localhost:8000`  
Swagger API docs: `http://localhost:8000/docs`

### Start the Frontend

In a **new terminal**:

```powershell
cd frontend
npm run dev
```

Frontend available at: `http://localhost:5173`

---

## Running with Docker

```powershell
# From project root
# Copy environment file first
copy backend\.env.example .env
# Edit .env with your API keys if desired

docker compose up --build
```

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8000`

---

## Initialise Threat Memory (RAG)

Before using similarity search, load the sample phishing database:

```powershell
# Option 1 — via API call
curl -X POST http://localhost:8000/api/memory/initialize

# Option 2 — via the UI
# Go to Threat Memory page → click "Initialise Memory Database"
```

This loads 15 curated phishing and legitimate email samples into ChromaDB.

---

## API Documentation

Full Swagger UI: `http://localhost:8000/docs`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | System component status |
| POST | `/api/analyze` | Analyse email from JSON |
| POST | `/api/analyze/file` | Analyse uploaded .eml file |
| GET | `/api/history` | Paginated analysis history |
| GET | `/api/analysis/{id}` | Full analysis by ID |
| GET | `/api/stats` | Aggregate statistics |
| POST | `/api/memory/initialize` | Load sample data into ChromaDB |
| GET | `/api/memory/status` | ChromaDB status |
| GET | `/api/demo/emails` | List demo scenarios |
| GET | `/api/demo/emails/{id}` | Get demo email content |

**Example request:**

```json
POST /api/analyze
{
  "email": {
    "from": "\"PayPal Security\" <security@paypa1-alerts.com>",
    "reply_to": "steal@attacker.tk",
    "subject": "URGENT: Your account has been limited",
    "body": "Click here to verify: http://paypa1-secure.tk/verify"
  }
}
```

**Example response:**

```json
{
  "id": "uuid",
  "fusion_result": {
    "risk_score": 92,
    "classification": "CRITICAL",
    "confidence": 0.94,
    "key_reasons": ["Domain paypa1-alerts.com impersonates paypal.com", "..."],
    "recommended_action": "IMMEDIATE THREAT — Delete this email...",
    "explanation": "..."
  },
  "header_result": { "risk_score": 85, ... },
  "content_result": { "risk_score": 72, ... },
  "url_result": { "risk_score": 90, ... },
  "memory_result": { "risk_score": 65, ... }
}
```

---

## Testing

```powershell
cd backend
venv\Scripts\activate
pytest -v
```

Test coverage:
- Header agent: spoofing, typosquatting, auth failures
- Content agent: urgency, credentials, prompt injection
- URL agent: malicious patterns, VT integration, legitimate URLs
- Fusion agent: all-high, all-safe, mixed signals
- API: valid/invalid/oversized inputs, all endpoints

---

## Demo Walkthrough

1. Start backend and frontend
2. Run `POST /api/memory/initialize` (or click in UI)
3. Go to **Analyse Email** page
4. Click **Load Demo Scenario** → select `PayPal Phishing`
5. Click **Analyse Email**
6. Observe the `CRITICAL` verdict with agent breakdown

Expected results:
| Demo | Expected |
|------|----------|
| PayPal Phishing | CRITICAL (≥85) |
| Microsoft Credential | HIGH RISK (≥55) |
| Invoice Fraud | HIGH RISK (≥55) |
| Apple Campaign Match | CRITICAL (≥80 with memory) |
| University Newsletter | SAFE (≤25) |
| Prompt Injection | HIGH RISK (injection flagged) |

---

## Security Considerations

- All email content is treated as **hostile untrusted input**
- Content agent wraps analysed email in explicit delimiters to prevent prompt injection
- Prompt injection patterns are detected and flagged as an attack indicator
- API keys are never exposed to the frontend
- File uploads are validated and size-limited (512KB default)
- CORS is restricted to the configured frontend URL
- No shell execution, no arbitrary code execution from email content
- HTML content from emails is stripped before display
- Error messages do not expose internal system details

---

## Fallback Behaviour

ThreatFusion AI is fully operational without any API keys:

| Service | Available | Unavailable |
|---------|-----------|-------------|
| Gemini | LLM content analysis | Regex/pattern heuristics |
| VirusTotal | Real URL reputation | Local URL risk scoring |
| ChromaDB | Historical campaign similarity | Empty memory (0 contribution) |

The UI displays a notice when fallback mode is active.

---

## Project Structure

```
ThreatFusion-AI/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app + lifespan
│   │   ├── config.py            # Settings from .env
│   │   ├── api/routes.py        # All REST endpoints
│   │   ├── agents/
│   │   │   ├── header_agent.py  # Rules-based header analysis
│   │   │   ├── content_agent.py # Gemini + heuristic fallback
│   │   │   ├── url_agent.py     # URL analysis + VirusTotal
│   │   │   ├── memory_agent.py  # ChromaDB RAG
│   │   │   └── fusion_agent.py  # Weighted score combiner
│   │   ├── graph/workflow.py    # Async orchestration
│   │   ├── schemas/analysis.py  # Pydantic models
│   │   ├── database/            # SQLAlchemy + SQLite
│   │   ├── services/            # Business logic + sample data
│   │   └── utils/               # Domain analyser, email parser
│   └── tests/                   # pytest test suite
│
├── frontend/
│   └── src/
│       ├── pages/               # Dashboard, Analyse, History, etc.
│       ├── components/          # RiskGauge, AgentCard, Timeline
│       ├── services/api.js      # Axios API client
│       ├── hooks/useAnalysis.js # Analysis state hook
│       └── utils/risk.js        # Risk colour utilities
│
├── docker/                      # Dockerfiles + nginx config
├── docker-compose.yml
└── README.md
```

---

## Troubleshooting

**`ModuleNotFoundError`** — Activate virtual environment first:
```powershell
venv\Scripts\activate
```

**`ChromaDB ONNX error on Windows`** — Install ONNX runtime:
```powershell
pip install onnxruntime
```

**`Gemini 429 Rate Limited`** — The free tier has limits. The system falls back to heuristics automatically.

**`CORS error in browser`** — Ensure `FRONTEND_URL=http://localhost:5173` in backend `.env`.

**`npm install fails`** — Use Node 18+. Run `node --version` to check.

**`Port 8000 in use`** — Change `BACKEND_PORT` in `.env` and update `vite.config.js` proxy target.

---

## Limitations

- Content analysis accuracy depends on Gemini API availability
- VirusTotal free tier: 4 requests/minute
- ChromaDB runs embedded (no separate service required)
- SQLite suitable for academic/demo use; use PostgreSQL for production
- URL shortener destinations cannot be checked without clicking

## Future Improvements

- BERT-based local phishing classifier to reduce Gemini dependency
- Attachment analysis (PDF, Office documents)
- Real-time webhook integration with email providers
- MITRE ATT&CK tactic mapping
- Team collaboration features
- PostgreSQL + Redis for production deployments
