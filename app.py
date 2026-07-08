from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import pkgutil
import importlib
from pathlib import Path
import config
import asyncio
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

app = FastAPI(title="nCrypt", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _custom_url_for(name, **kw):
    if name == 'static':
        return f"/static/{kw.get('filename', kw.get('path', ''))}"
    if name == 'index':
        return '/'
    if name == 'list_ciphers':
        return '/ciphers'
    if name == 'cipher_page':
        cid = kw.get('cipher_id')
        return f"/cipher/{cid}"
    return f"/{name}"

CIPHER_REGISTRY = {}
_executor = ThreadPoolExecutor(max_workers=4)


def load_ciphers():
    import ciphers
    for _, modname, _ in pkgutil.iter_modules(ciphers.__path__):
        if modname.startswith('_') or modname == 'interface':
            continue
        try:
            module = importlib.import_module(f'ciphers.{modname}')
            if hasattr(module, 'register'):
                result = module.register()
                if isinstance(result, list):
                    for c in result:
                        CIPHER_REGISTRY[c.id] = c
                else:
                    CIPHER_REGISTRY[result.id] = result
        except Exception as e:
            print(f"[!] Failed: {modname}: {e}")
    print(f"[+] Loaded {len(CIPHER_REGISTRY)} cipher modules")


class TextInput(BaseModel):
    text: Optional[str] = ''
    cipher_id: Optional[str] = None
    mode: Optional[str] = 'decrypt'
    key: Optional[str] = ''
    crib: Optional[str] = ''
    target_plaintext: Optional[str] = ''
    disabled_ciphers: Optional[List[str]] = None
    debug: Optional[bool] = False


def _apply_target_priority(results, target_plaintext):
    target = (target_plaintext or '').strip().lower()
    if not target:
        return results

    boosted = []
    for r in results:
        pt = getattr(r, 'plaintext', '') or ''
        hit = target in pt.lower()
        if hit:
            r.confidence = min(100.0, max(float(r.confidence), 96.0))
            r.metadata = dict(getattr(r, 'metadata', {}) or {})
            r.metadata['target_hit'] = True
        boosted.append(r)

    boosted.sort(key=lambda x: ((target in (x.plaintext or '').lower()), x.confidence), reverse=True)
    return boosted


def _ctx(request, **extra):
    return {"request": request, "url_for": _custom_url_for, "ciphers": CIPHER_REGISTRY, **extra}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", _ctx(request))


@app.get("/ciphers", response_class=HTMLResponse)
async def list_ciphers(request: Request):
    return templates.TemplateResponse(request, "list.html", _ctx(request))


@app.get("/cipher/{cipher_id}", response_class=HTMLResponse)
async def cipher_page(request: Request, cipher_id: str):
    cipher = CIPHER_REGISTRY.get(cipher_id)
    if not cipher:
        return HTMLResponse("Not found", 404)
    return templates.TemplateResponse(request, "cipher.html", _ctx(request, cipher=cipher))


@app.post("/api/analyze")
async def analyze(data: TextInput):
    text = data.text or ''
    if not text.strip():
        return {"results": []}
    results = []
    for cid, cipher in CIPHER_REGISTRY.items():
        try:
            score = cipher.identify(text)
            if score > 0.05:
                results.append({"id": cid, "name": cipher.name, "category": cipher.category, "score": round(score, 3)})
        except Exception:
            pass
    results.sort(key=lambda x: x['score'], reverse=True)
    return {"results": results[:20]}


@app.post("/api/process")
async def process_cipher(data: TextInput):
    cipher = CIPHER_REGISTRY.get(data.cipher_id)
    if not cipher:
        return JSONResponse({"error": "Cipher not found"}, 404)
    text = data.text or ''
    try:
        if cipher.id == 'recursive_solver' and data.mode != 'encrypt':
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                _executor,
                lambda: cipher.crack(
                    text,
                    registry=CIPHER_REGISTRY,
                    key=data.key,
                    crib=data.crib,
                    disabled_ciphers=data.disabled_ciphers or [],
                ),
            )
            if not results:
                return {"result": "(no solution found)"}
            best = results[0]
            path = ' -> '.join(best.metadata.get('path', [])) if best.metadata else ''
            header = f"# {round(best.confidence, 1)}  {path}\n" if path else ''
            return {"result": header + best.plaintext}

        if data.mode == 'encrypt':
            result = cipher.encrypt(text, data.key)
        else:
            result = cipher.decrypt(text, data.key)
        return {"result": result}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 400)


@app.post("/api/crack")
async def crack_cipher(data: TextInput):
    cipher = CIPHER_REGISTRY.get(data.cipher_id)
    if not cipher:
        return JSONResponse({"error": "Cipher not found"}, 404)
    text = data.text or ''
    try:
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            _executor,
            lambda: cipher.crack(
                text,
                registry=CIPHER_REGISTRY,
                key=data.key,
                crib=data.crib,
                disabled_ciphers=data.disabled_ciphers or [],
                target_plaintext=data.target_plaintext,
                debug=data.debug,
            ),
        )
        results = _apply_target_priority(results, data.target_plaintext)
        payload = {"results": [r.to_dict() for r in results]}
        if data.debug and hasattr(cipher, 'last_debug'):
            payload['debug'] = getattr(cipher, 'last_debug', {})
        return payload
    except Exception as e:
        return JSONResponse({"error": str(e)}, 400)


@app.post("/api/frequency")
async def frequency_analysis(data: TextInput):
    from utils.analysis import (calculate_frequencies, calculate_ioc, entropy,
                                chi_squared_score, score_quadgram,
                                score_text_english_likelihood, get_ngrams, clean_text)
    text = data.text or ''
    clean = clean_text(text)
    ioc = calculate_ioc(text)
    if ioc > 0.06:
        verdict = "Monoalphabetic / English-like"
    elif ioc > 0.045:
        verdict = "Polyalphabetic cipher likely"
    elif ioc > 0.03:
        verdict = "Near-random / Long key"
    else:
        verdict = "Random or non-alphabetic"

    bigrams = get_ngrams(text, 2).most_common(10)
    trigrams = get_ngrams(text, 3).most_common(10)

    return {
        "ioc": round(ioc, 4),
        "entropy": round(entropy(text), 2),
        "chi_squared": round(chi_squared_score(text), 2),
        "quadgram_fitness": round(score_quadgram(text), 2),
        "english_score": round(score_text_english_likelihood(text), 1),
        "length": len(text),
        "alpha_length": len(clean),
        "ioc_verdict": verdict,
        "bigrams": [{"ngram": ng, "count": c} for ng, c in bigrams],
        "trigrams": [{"ngram": ng, "count": c} for ng, c in trigrams],
    }


@app.post("/api/bruteforce")
async def universal_bruteforce(data: TextInput):
    from bruteforce.engine import run_universal_bruteforce
    text = data.text or ''
    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(
        _executor,
        lambda: run_universal_bruteforce(
            text,
            CIPHER_REGISTRY,
            max_overall=50,
            disabled_ciphers=data.disabled_ciphers or [],
            target_plaintext=data.target_plaintext,
        ),
    )
    return {"results": [r.to_dict() for r in results]}


@app.post("/api/solve")
async def solve(data: TextInput):
    text = data.text or ''
    mode = data.mode or 'recursive'

    if mode == 'recursive':
        solver = CIPHER_REGISTRY.get('recursive_solver')
        if solver:
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                _executor,
                lambda: solver.crack(
                    text,
                    registry=CIPHER_REGISTRY,
                    key=data.key,
                    crib=data.crib,
                    disabled_ciphers=data.disabled_ciphers or [],
                    target_plaintext=data.target_plaintext,
                    debug=data.debug,
                ),
            )
            results = _apply_target_priority(results, data.target_plaintext)

            payload = {"results": [r.to_dict() for r in results]}
            if data.debug and hasattr(solver, 'last_debug'):
                payload['debug'] = getattr(solver, 'last_debug', {})
            return payload

    if mode == 'bruteforce':
        from bruteforce.engine import run_universal_bruteforce
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            _executor,
            lambda: run_universal_bruteforce(
                text,
                CIPHER_REGISTRY,
                disabled_ciphers=data.disabled_ciphers or [],
                target_plaintext=data.target_plaintext,
            ),
        )
        results = _apply_target_priority(results, data.target_plaintext)
        return {"results": [r.to_dict() for r in results]}

    return {"results": []}


@app.post("/api/auto_process")
async def auto_process(data: TextInput):
    from utils.analysis import (calculate_ioc, entropy, score_text_english_likelihood, clean_text)
    text = data.text or ''
    if not text.strip():
        return {"stats": {}, "matches": [], "quick_results": []}

    clean = clean_text(text)
    ioc = calculate_ioc(text)
    eng = score_text_english_likelihood(text)

    stats = {
        "length": len(text),
        "alpha": len(clean),
        "entropy": round(entropy(text), 2),
        "ioc": round(ioc, 4),
        "english": round(eng, 1),
    }

    matches = []
    for cid, cipher in CIPHER_REGISTRY.items():
        try:
            score = cipher.identify(text)
            if score > 0.05:
                matches.append({"id": cid, "name": cipher.name, "category": cipher.category, "score": round(score, 3)})
        except Exception:
            pass
    matches.sort(key=lambda x: x['score'], reverse=True)

    quick_results = []
    for m in matches[:5]:
        cipher = CIPHER_REGISTRY.get(m['id'])
        if not cipher:
            continue
        try:
            cracks = cipher.crack(text, registry=CIPHER_REGISTRY)
            for r in cracks[:2]:
                if r.confidence > 15:
                    quick_results.append({
                        "cipher": m['name'],
                        "cipher_id": m['id'],
                        "plaintext": r.plaintext[:500],
                        "confidence": r.confidence,
                        "key": str(r.key) if r.key else None,
                    })
        except Exception:
            pass
    quick_results.sort(key=lambda x: x['confidence'], reverse=True)

    return {"stats": stats, "matches": matches[:15], "quick_results": quick_results[:10]}


@app.post("/api/render_grid")
async def render_grid(data: TextInput):
    cipher = CIPHER_REGISTRY.get(data.cipher_id)
    if not cipher:
        return {"grid": None}
    try:
        grid = cipher.generate_grid(data.key)
        return {"grid": grid}
    except Exception:
        return {"grid": None}


load_ciphers()

if __name__ == '__main__':
    import os
    import uvicorn
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '5000'))
    uvicorn.run(app, host=host, port=port)
