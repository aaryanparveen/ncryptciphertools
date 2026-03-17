document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.createElement('canvas');
    canvas.id = 'particle-canvas';
    canvas.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:-1;';
    document.body.appendChild(canvas);

    const ctx = canvas.getContext('2d');
    const symbols = '01ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
    let width, height;
    const particles = [];
    const maxParticles = window.innerWidth < 768 ? 12 : 25;
    const connectionDist = 110;
    let mouseX = -1000, mouseY = -1000;

    function resize() { width = canvas.width = window.innerWidth; height = canvas.height = window.innerHeight; }
    function createParticle() {
        return {
            x: Math.random() * width, y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25,
            char: symbols[Math.floor(Math.random() * symbols.length)],
            size: Math.random() * 9 + 7, opacity: Math.random() * 0.12 + 0.02,
            depth: Math.random() * 2 + 1
        };
    }
    function init() { resize(); for (let i = 0; i < maxParticles; i++) particles.push(createParticle()); }
    function draw() {
        ctx.clearRect(0, 0, width, height);
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x, dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < connectionDist) {
                    const alpha = (1 - dist / connectionDist) * 0.03;
                    ctx.beginPath(); ctx.strokeStyle = `rgba(196, 48, 80, ${alpha})`;
                    ctx.lineWidth = 0.5; ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y); ctx.stroke();
                }
            }
        }
        particles.forEach(p => {
            const mdx = (p.x - mouseX) / width, mdy = (p.y - mouseY) / height;
            ctx.save(); ctx.globalAlpha = p.opacity;
            ctx.fillStyle = 'rgba(196, 48, 80, 1)';
            ctx.font = `${p.size}px 'JetBrains Mono', monospace`;
            ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
            ctx.fillText(p.char, p.x + mdx * 12 * p.depth, p.y + mdy * 12 * p.depth);
            ctx.restore();
        });
    }
    function update() {
        particles.forEach(p => {
            p.x += p.vx; p.y += p.vy;
            if (p.x < -20) p.x = width + 20; if (p.x > width + 20) p.x = -20;
            if (p.y < -20) p.y = height + 20; if (p.y > height + 20) p.y = -20;
        });
    }
    function loop() { update(); draw(); requestAnimationFrame(loop); }

    window.addEventListener('resize', resize);
    document.addEventListener('mousemove', e => { mouseX = e.clientX; mouseY = e.clientY; });
    init(); loop();
});
