import json
import re
import os


def _get_client():
    from openai import OpenAI
    api_key = os.environ.get('NVIDIA_API_KEY', '')
    if not api_key:
        return None, None
    model = os.environ.get('NVIDIA_MODEL', 'nvidia/llama-3.3-nemotron-super-49b-v1')
    client = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=api_key)
    return client, model


def get_ai_evaluation(candidates, api_key=None):
    client, model = _get_client()
    if not client:
        return {
            "top_candidates": candidates[:5],
            "reasoning": "No NVIDIA_API_KEY configured",
            "flag_found": False,
        }

    candidates_text = ""
    for idx, cand in enumerate(candidates[:30]):
        pt = str(cand.get("plaintext", ""))[:800]
        score = cand.get("confidence", 0)
        c_name = cand.get("metadata", {}).get("cipher_name", "Unknown")
        key = cand.get("key", "None")
        candidates_text += f"\n--- CANDIDATE {idx} ---\nCipher: {c_name} | Key: {key} | Score: {score}\nText: {pt}\n"

    system_msg = (
        "You are an expert CTF cryptanalysis AI. Analyze candidate decryptions. "
        "For top 3 best candidates, say if each IS plaintext or needs MORE decoding. "
        "Look for flag{...}, CTF{...}, readable English. "
        "Output ONLY valid JSON: {\"best_candidates\": [{\"index\": int, \"is_plaintext\": bool, \"reasoning\": \"...\"}], "
        "\"flag_found\": bool, \"overall_assessment\": \"...\"}"
    )

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": f"Evaluate these {len(candidates[:30])} decryption candidates:\n{candidates_text}\n\nOutput only JSON."}
            ],
            temperature=0.1,
            max_tokens=1024
        )

        raw = response.choices[0].message.content or "{}"
        m = re.search(r'```json\s*(.*?)\s*```', raw, re.DOTALL)
        raw = m.group(1) if m else raw.strip()
        result = json.loads(raw)

        top_candidates = []
        for b in result.get("best_candidates", [])[:3]:
            idx = b.get("index", -1)
            if 0 <= idx < len(candidates):
                cand = dict(candidates[idx])
                cand['metadata'] = dict(cand.get('metadata', {}))
                cand['metadata']['ai_reasoning'] = b.get("reasoning", "")
                cand['metadata']['ai_selected'] = True
                cand['metadata']['is_plaintext'] = b.get("is_plaintext", False)
                if b.get("is_plaintext"):
                    cand['confidence'] = cand.get('confidence', 0) + 1000
                top_candidates.append(cand)

        return {
            "top_candidates": top_candidates,
            "reasoning": result.get("overall_assessment", ""),
            "flag_found": result.get("flag_found", False),
        }
    except Exception as e:
        return {
            "top_candidates": candidates[:5],
            "reasoning": f"AI evaluation failed: {e}",
            "flag_found": False,
        }


def orchestrate_solve(text, registry, max_depth=5):
    from bruteforce.engine import run_universal_bruteforce

    all_solutions = []
    texts_to_process = [(text, [], 0)]
    visited = {text[:500]}

    for _ in range(max_depth):
        if not texts_to_process:
            break
        next_round = []
        for current_text, current_path, depth in texts_to_process:
            brute_results = run_universal_bruteforce(current_text, registry, max_overall=30)
            candidates = [r.to_dict() for r in brute_results]
            if not candidates:
                continue

            client, _ = _get_client()
            if not client:
                for c in candidates[:5]:
                    if c.get('confidence', 0) > 40:
                        c_path = current_path + [c.get('metadata', {}).get('cipher_name', '?')]
                        c['metadata'] = c.get('metadata', {})
                        c['metadata']['path'] = c_path
                        c['metadata']['depth'] = depth + 1
                        all_solutions.append(c)
                continue

            ai_result = get_ai_evaluation(candidates)
            for cand in ai_result.get("top_candidates", []):
                pt = cand.get('plaintext', '')
                meta = cand.get('metadata', {})
                c_path = current_path + [meta.get('cipher_name', 'Unknown')]
                cand['metadata']['path'] = c_path
                cand['metadata']['depth'] = depth + 1

                if meta.get('is_plaintext') or cand.get('confidence', 0) > 1000:
                    all_solutions.append(cand)
                elif ai_result.get('flag_found'):
                    all_solutions.append(cand)
                else:
                    pt_key = pt[:500]
                    if pt_key not in visited and depth + 1 < max_depth:
                        visited.add(pt_key)
                        next_round.append((pt, c_path, depth + 1))
                    all_solutions.append(cand)
        texts_to_process = next_round

    all_solutions.sort(key=lambda x: x.get('confidence', 0), reverse=True)
    unique, seen = [], set()
    for s in all_solutions:
        pt = s.get('plaintext', '')[:500]
        if pt not in seen:
            seen.add(pt)
            unique.append(s)

    if not unique:
        return {"solved": False, "flag": "", "reasoning": "No candidates found.", "candidates": []}

    best = unique[0]
    return {
        "solved": best.get('confidence', 0) > 50 or best.get('metadata', {}).get('is_plaintext'),
        "flag": best.get('plaintext', ''),
        "reasoning": best.get('metadata', {}).get('ai_reasoning', 'Engine-scored result'),
        "candidates": unique[:10]
    }
