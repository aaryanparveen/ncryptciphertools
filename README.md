# nCrypt

nCrypt is a FastAPI cryptanalysis suite for code-breaking and LLM aided recursive solving.

## Features

- FastAPI web interface with Jinja templates
- Broad cipher catalog with encrypt, decrypt, and crack flows
- Universal recursive solver
  - engine top-3 candidate expansion
  - AI top-3 re-ranking
  - recursive chaining up to configured depth
  - target plaintext prioritization
- Keyed-cipher brute force integrations
- Calibrated English-likelihood scoring with n-gram corpus
- Real-time auto-processing endpoint
- Optional NVIDIA OpenAI-compatible AI support

## Requirements

- Python 3.10+
- pip

## Local Run

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Create local environment file:

```bash
copy .env.example .env
```

3. Start server:

```bash
uvicorn app:app --host 0.0.0.0 --port 5000
```

4. Open:

```text
http://127.0.0.1:5000
```

## Docker Run

No API key is required to boot.

```bash
docker compose up --build
```

Open `http://127.0.0.1:5000`.

## Environment

- `NVIDIA_API_KEY`: optional AI key
- `NVIDIA_MODEL`: default `qwen/qwen3-235b-a22b`
- `SECRET_KEY`: app secret
- `HOST`: bind host
- `PORT`: bind port

## API Endpoints

- `POST /api/analyze`
- `POST /api/process`
- `POST /api/crack`
- `POST /api/solve`
- `POST /api/bruteforce`
- `POST /api/frequency`
- `POST /api/auto_process`
- `POST /api/ai_solve`

## Target Plaintext

Crack and solve endpoints support `target_plaintext` in request JSON. Matching outputs receive priority and confidence boost.

Example:

```json
{
  "text": "RIJVS UYVJN",
  "mode": "recursive",
  "target_plaintext": "HELLO WORLD"
}
```

## Layout

- `app.py`: API and page routes
- `ciphers/`: cipher implementations
- `bruteforce/`: specialized cracking engines
- `utils/`: scoring, corpora, AI orchestration
- `templates/`: web templates
- `static/`: CSS and JavaScript

## Notes

- App runs without AI credentials.
- With `cipheydists` installed, scoring quality is significantly better for long text.
