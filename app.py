from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
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

app = FastAPI(
    title="nCrypt",
    description="Cryptanalysis API: classical and modern ciphers, a recursive multi-layer auto-solver, "
                "frequency analysis, and a symmetric crypto suite (AES, Camellia, ChaCha20 and more). "
                "The web UI served at / calls these same endpoints. Interactive docs: /docs and /redoc.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
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

from ciphers.recursive import DEFAULT_DISABLED


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
    text: Optional[str] = Field('', description="Text to process (plaintext or ciphertext)")
    cipher_id: Optional[str] = Field(None, description="Registered cipher id, e.g. caesar_cipher, vigenere_cipher, recursive_solver")
    mode: Optional[str] = Field('decrypt', description="encrypt/decrypt for /api/process; recursive/bruteforce for /api/solve")
    key: Optional[str] = Field('', description="Cipher key; for recursive_solver this is the max search depth (1-12)")
    crib: Optional[str] = Field('', description="Known plaintext substring to prioritise while solving")
    target_plaintext: Optional[str] = Field('', description="Boost any result that contains this text")
    disabled_ciphers: Optional[List[str]] = Field(None, description="Cipher ids to skip during the auto-solver search")
    debug: Optional[bool] = Field(False, description="Include solver debug information in the response")


class ModernInput(BaseModel):
    action: Optional[str] = Field('encrypt', description="encrypt or decrypt")
    algorithm: Optional[str] = Field('AES-256', description="AES-128/192/256, Camellia-128/192/256, SM4, SEED, Blowfish, Triple DES (168/112), DES, CAST-128, IDEA, RC2, ChaCha20, ChaCha20-Poly1305, Salsa20, RC4")
    mode: Optional[str] = Field('CBC', description="ECB, CBC, CFB, OFB, CTR; GCM and EAX are AES-only; ignored for stream ciphers")
    text: Optional[str] = Field('', max_length=2_000_000, description="Plaintext to encrypt, or ciphertext (in data_format) to decrypt")
    key: Optional[str] = Field('', max_length=8192, description="Key, interpreted according to key_format")
    key_format: Optional[str] = Field('UTF-8', description="UTF-8, Hex, Base64, or Passphrase (SHA-256 derived to the key size)")
    iv: Optional[str] = Field('', max_length=1024, description="Hex IV/nonce; auto-generated on encrypt and kept in the field, required to decrypt non-ECB modes")
    data_format: Optional[str] = Field('Base64', description="Base64 or Hex encoding of the ciphertext")


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
    return {"request": request, "url_for": _custom_url_for, "ciphers": CIPHER_REGISTRY,
            "default_disabled": DEFAULT_DISABLED, **extra}


@app.get("/", response_class=HTMLResponse, tags=["Web"], summary="Cipher identifier home page")
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", _ctx(request))


@app.get("/ciphers", response_class=HTMLResponse, tags=["Web"], summary="Tools / cipher catalog page")
async def list_ciphers(request: Request):
    return templates.TemplateResponse(request, "list.html", _ctx(request))


@app.get("/cipher/{cipher_id}", response_class=HTMLResponse, tags=["Web"], summary="Individual cipher workbench page")
async def cipher_page(request: Request, cipher_id: str):
    cipher = CIPHER_REGISTRY.get(cipher_id)
    if not cipher:
        return HTMLResponse("Not found", 404)
    if cipher_id == 'modern_cipher':
        return templates.TemplateResponse(request, "modern.html", _ctx(request, cipher=cipher, spec=cipher.ui_spec()))
    return templates.TemplateResponse(request, "cipher.html", _ctx(request, cipher=cipher))


@app.post("/api/analyze", tags=["Analysis"], summary="Identify likely ciphers for a ciphertext")
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


@app.post("/api/process", tags=["Ciphers"], summary="Encrypt/decrypt with one cipher, or run the recursive solver")
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
        return {"error": str(e)}


@app.post("/api/crack", tags=["Solve"], summary="Crack one specific cipher (supports crib and target plaintext)")
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


@app.post("/api/frequency", tags=["Analysis"], summary="Frequency analysis: IoC, entropy, chi-squared, quadgram fitness, n-grams")
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


@app.post("/api/bruteforce", tags=["Solve"], summary="Universal bruteforce across all enabled ciphers")
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


@app.post("/api/solve", tags=["Solve"], summary="Auto-solve ciphertext; mode=recursive|bruteforce, key = max depth (1-12) for recursive")
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


@app.post("/api/auto_process", tags=["Analysis"], summary="One-shot: stats + cipher matches + quick crack results")
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


@app.post("/api/render_grid", tags=["Ciphers"], summary="Render a cipher's key grid (Polybius, Playfair, ADFGX, ...)")
async def render_grid(data: TextInput):
    cipher = CIPHER_REGISTRY.get(data.cipher_id)
    if not cipher:
        return {"grid": None}
    try:
        grid = cipher.generate_grid(data.key)
        return {"grid": grid}
    except Exception:
        return {"grid": None}


@app.post("/api/modern", tags=["Modern Crypto"], summary="Symmetric encrypt/decrypt across AES, Camellia, SM4, ChaCha20 and more (ECB/CBC/CFB/OFB/CTR/GCM/EAX)")
async def modern_process(data: ModernInput):
    cipher = CIPHER_REGISTRY.get('modern_cipher')
    if not cipher:
        return JSONResponse({"error": "unavailable"}, 404)
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor,
            lambda: cipher.run(data.action, data.algorithm, data.mode, data.text,
                               data.key, data.key_format, data.iv, data.data_format),
        )
    except Exception as e:
        return {"error": str(e)}


load_ciphers()

if __name__ == '__main__':
    import os
    import uvicorn
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '5000'))
    uvicorn.run(app, host=host, port=port)
