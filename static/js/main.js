

document.addEventListener('DOMContentLoaded', () => {
    console.log('nCrypt v2.0 loaded.');

    const navbar = document.getElementById('navbar');
    if (navbar) {
        let lastScroll = 0;
        window.addEventListener('scroll', () => {
            const scrollY = window.scrollY;
            if (scrollY > 50) {
                navbar.style.borderBottomColor = 'rgba(255,255,255,0.06)';
                navbar.style.boxShadow = '0 4px 30px rgba(0,0,0,0.4)';
            } else {
                navbar.style.borderBottomColor = 'rgba(255,255,255,0.04)';
                navbar.style.boxShadow = '0 1px 20px rgba(0,0,0,0.3)';
            }
            lastScroll = scrollY;
        }, { passive: true });
    }

    if (typeof gsap !== 'undefined') {
        document.querySelectorAll('.bento-card').forEach(card => {
            card.addEventListener('mouseenter', () => {
                gsap.to(card, { y: -4, duration: 0.25, ease: 'power2.out' });
            });
            card.addEventListener('mouseleave', () => {
                gsap.to(card, { y: 0, duration: 0.35, ease: 'power2.out' });
            });
        });

        document.querySelectorAll('.btn-primary, .btn-solve').forEach(btn => {
            btn.addEventListener('mouseenter', () => {
                gsap.to(btn, { y: -1, scale: 1.02, duration: 0.2, ease: 'power2.out' });
            });
            btn.addEventListener('mouseleave', () => {
                gsap.to(btn, { y: 0, scale: 1, duration: 0.25, ease: 'power2.out' });
            });
        });

        document.querySelectorAll('.tab-btn').forEach(tab => {
            tab.addEventListener('click', () => {
                gsap.fromTo(tab, { scale: 0.95 }, { scale: 1, duration: 0.2, ease: 'back.out(2)' });
            });
        });

        document.querySelectorAll('.category-tab').forEach(pill => {
            pill.addEventListener('mouseenter', () => {
                gsap.to(pill, { scale: 1.04, duration: 0.15, ease: 'power2.out' });
            });
            pill.addEventListener('mouseleave', () => {
                gsap.to(pill, { scale: 1, duration: 0.2, ease: 'power2.out' });
            });
        });

        const footer = document.querySelector('.footer');
        if (footer) {
            const footerObserver = new IntersectionObserver(entries => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        gsap.from(footer, { opacity: 0, y: 15, duration: 0.5, ease: 'power2.out' });
                        footerObserver.unobserve(footer);
                    }
                });
            }, { threshold: 0.3 });
            footerObserver.observe(footer);
        }
    }

    document.querySelectorAll('textarea.form-control').forEach(ta => {
        ta.addEventListener('input', () => {
            ta.style.height = 'auto';
            ta.style.height = Math.max(ta.scrollHeight, 170) + 'px';
        });
    });

    document.querySelectorAll('.editor-card').forEach(card => {
        const textarea = card.querySelector('textarea');
        if (textarea) {
            textarea.addEventListener('focus', () => {
                if (typeof gsap !== 'undefined') {
                    gsap.to(card, {
                        borderColor: 'rgba(196,48,80,0.25)',
                        boxShadow: '0 0 0 3px rgba(196,48,80,0.06), 0 2px 8px rgba(0,0,0,0.4)',
                        duration: 0.3, ease: 'power2.out'
                    });
                }
            });
            textarea.addEventListener('blur', () => {
                if (typeof gsap !== 'undefined') {
                    gsap.to(card, {
                        borderColor: 'rgba(255,255,255,0.06)',
                        boxShadow: '0 2px 8px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.04)',
                        duration: 0.3, ease: 'power2.out'
                    });
                }
            });
        }
    });
});
