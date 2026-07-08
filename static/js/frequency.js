
const FrequencyAnalysis = (() => {
    const ENGLISH_FREQS = {
        A:8.167,B:1.492,C:2.782,D:4.253,E:12.702,F:2.228,G:2.015,H:6.094,
        I:6.966,J:0.153,K:0.772,L:4.025,M:2.406,N:6.749,O:7.507,P:1.929,
        Q:0.095,R:5.987,S:6.327,T:9.056,U:2.758,V:0.978,W:2.360,X:0.150,
        Y:1.974,Z:0.074
    };
    const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    function cleanText(text) { return text.toUpperCase().replace(/[^A-Z]/g, ''); }

    function getFrequencies(text) {
        const clean = cleanText(text);
        const counts = {}; LETTERS.split('').forEach(c => counts[c] = 0);
        for (const c of clean) { if (counts[c] !== undefined) counts[c]++; }
        const total = clean.length || 1;
        const freqs = {};
        for (const c of LETTERS) freqs[c] = (counts[c] / total) * 100;
        return freqs;
    }

    function calculateIoC(text) {
        const clean = cleanText(text);
        if (clean.length <= 1) return 0;
        const counts = {};
        for (const c of clean) counts[c] = (counts[c] || 0) + 1;
        let num = 0;
        for (const c in counts) num += counts[c] * (counts[c] - 1);
        return num / (clean.length * (clean.length - 1));
    }

    function getTopBigrams(text, n = 8) {
        const clean = cleanText(text);
        if (clean.length < 2) return [];
        const counts = {};
        for (let i = 0; i < clean.length - 1; i++) {
            const bg = clean[i] + clean[i + 1];
            counts[bg] = (counts[bg] || 0) + 1;
        }
        return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, n)
            .map(([bg, count]) => ({ bigram: bg, count }));
    }

    function renderChart(targetEl, text) {
        const freqs = getFrequencies(text);
        const maxFreq = Math.max(...Object.values(freqs), 1);
        const maxExpected = Math.max(...Object.values(ENGLISH_FREQS));
        const scaleMax = Math.max(maxFreq, maxExpected);
        let html = '<div class="freq-bar-container">';
        for (const letter of LETTERS) {
            const pct = (freqs[letter] / scaleMax) * 100;
            html += `<div class="freq-bar-wrap" title="${letter}: ${freqs[letter].toFixed(1)}% (exp: ${ENGLISH_FREQS[letter].toFixed(1)}%)"><div class="freq-bar" style="height:${pct}%"></div><div class="freq-label">${letter}</div></div>`;
        }
        html += '</div>';
        targetEl.innerHTML = html;
    }

    function renderIoC(targetEl, text) {
        const ioc = calculateIoC(text);
        const cls = ioc > 0.06 ? 'Monoalphabetic / English' : ioc > 0.045 ? 'Polyalphabetic' : ioc > 0.03 ? 'Near-random' : 'Random';
        targetEl.innerHTML = `<span class="ioc-label">IoC</span><span class="ioc-value">${ioc.toFixed(4)}</span><span class="ioc-sep" style="color:var(--tx-3);font-size:0.7rem;">${cls}</span>`;
    }

    function renderBigrams(targetEl, text) {
        const bigrams = getTopBigrams(text);
        if (!bigrams.length) { targetEl.innerHTML = '<span style="color:var(--tx-3);font-size:0.78rem;">Type text to see bigrams</span>'; return; }
        targetEl.innerHTML = bigrams.map(b =>
            `<span style="display:inline-flex;align-items:center;gap:3px;padding:2px 7px;background:var(--glass-bg);border:var(--border);border-radius:4px;font-family:var(--mono);font-size:0.73rem;margin:1px;"><strong>${b.bigram}</strong><span style="color:var(--tx-3)">${b.count}</span></span>`
        ).join('');
    }

    return { renderChart, renderIoC, renderBigrams, getFrequencies, calculateIoC };
})();
