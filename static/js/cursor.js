const cursor = document.createElement('div');
cursor.id = 'custom-cursor';
document.body.appendChild(cursor);

if (window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
    document.documentElement.classList.add('has-custom-cursor');
}

const cursorDot = document.createElement('div');
cursorDot.id = 'custom-cursor-dot';
document.body.appendChild(cursorDot);
window.originalDPR = window.originalDPR || window.devicePixelRatio;
let mouse = { x: -100, y: -100 };
let pos = { x: -100, y: -100 };
let posDot = { x: -100, y: -100 };
let hasMoved = false;
let currentRotation = 0;

window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    if (!hasMoved) {
        pos.x = mouse.x;
        pos.y = mouse.y;
        posDot.x = mouse.x;
        posDot.y = mouse.y;
        hasMoved = true;
    }
});

const setX = gsap.quickSetter(cursor, "x", "px");
const setY = gsap.quickSetter(cursor, "y", "px");
const setScaleX = gsap.quickSetter(cursor, "scaleX");
const setScaleY = gsap.quickSetter(cursor, "scaleY");
const setRotation = gsap.quickSetter(cursor, "rotation", "deg");
const setBorderRadius = gsap.quickSetter(cursor, "borderRadius");
const setBgColor = gsap.quickSetter(cursor, "backgroundColor");
const setMixBlendMode = gsap.quickSetter(cursor, "mixBlendMode");
const setBorder = gsap.quickSetter(cursor, "border");
const setWidth = gsap.quickSetter(cursor, "width", "px");
const setHeight = gsap.quickSetter(cursor, "height", "px");

const setDotX = gsap.quickSetter(cursorDot, "x", "px");
const setDotY = gsap.quickSetter(cursorDot, "y", "px");
const setDotWidth = gsap.quickSetter(cursorDot, "width", "px");
const setDotHeight = gsap.quickSetter(cursorDot, "height", "px");
const BASE_SIZE = 20;
function getZoom() {
    return window.devicePixelRatio / (window.screen.availWidth / window.innerWidth) || window.devicePixelRatio;
}
function getZoomScale() {
    if (window.visualViewport) {
        return window.visualViewport.scale;
    }
    return 1;
}
const baseDPR = window.devicePixelRatio;
function getZoomCompensation() {
    return baseDPR / window.devicePixelRatio;
}
let isHovering = false;
let hoverTarget = null;
let targetScale = 1;
let morphRadius = '50%';

const handleHoverEnter = (e) => {
    isHovering = true;
    hoverTarget = e.target;
    targetScale = 1.3;
    morphRadius = '50%';
    if (e.target.classList.contains('dash-card-head') || e.target.closest('button, a, .tool-card, .file-type-pill')) {
        targetScale = 1.6;
    }
};

const handleHoverLeave = () => {
    isHovering = false;
    hoverTarget = null;
    targetScale = 1;
    morphRadius = '50%';
};

const attachInteractivity = () => {
    const interactables = document.querySelectorAll('a, button, .dash-card-head, .tool-card, .file-type-pill');
    interactables.forEach(el => {
        el.removeEventListener('mouseenter', handleHoverEnter);
        el.removeEventListener('mouseleave', handleHoverLeave);
        el.addEventListener('mouseenter', handleHoverEnter);
        el.addEventListener('mouseleave', handleHoverLeave);
        el.style.cursor = 'none';
        Array.from(el.children).forEach(child => { if (child.style) child.style.cursor = 'none'; });
    });
};
setTimeout(attachInteractivity, 500);
function lerpAngle(from, to, t) {
    let diff = to - from;
    while (diff > 180) diff -= 360;
    while (diff < -180) diff += 360;
    return from + diff * t;
}
let smoothScaleX = 1;
let smoothScaleY = 1;
let smoothBorderOpacity = 0;
let smoothBgAlpha = 1;
let smoothMixBlend = 1;
function smoothDamp(speed, deltaRatio) {
    return 1.0 - Math.pow(1.0 - speed, deltaRatio);
}

gsap.ticker.add(() => {
    if (!hasMoved) return;

    const deltaRatio = gsap.ticker.deltaRatio(60);
    const posDt = smoothDamp(0.15, deltaRatio);
    pos.x += (mouse.x - pos.x) * posDt;
    pos.y += (mouse.y - pos.y) * posDt;
    const posDotDt = smoothDamp(0.6, deltaRatio);
    posDot.x += (mouse.x - posDot.x) * posDotDt;
    posDot.y += (mouse.y - posDot.y) * posDotDt;
    const vx = mouse.x - pos.x;
    const vy = mouse.y - pos.y;
    const velocity = Math.sqrt(vx * vx + vy * vy) / deltaRatio;
    const sizeMultiplier = (smoothScaleX + smoothScaleY) / 2;
    const stretch = Math.min(velocity * 0.008 * sizeMultiplier, 0.3 * sizeMultiplier);
    const velocityDeformX = 1 + stretch;
    const velocityDeformY = 1 - (stretch * 0.3);

    let velocityRotation = currentRotation;
    if (velocity > 2) {
        velocityRotation = Math.atan2(vy, vx) * (180 / Math.PI);
    }

    let wantScaleX = targetScale;
    let wantScaleY = targetScale;
    let wantRotation = currentRotation;
    let wantMixBlend = 1;
    let wantBorderStyle = 0;
    let wantBgAlpha = 1;

    let nearestDot = null;
    let minDist = Infinity;
    const dots = document.querySelectorAll('.dot');
    dots.forEach(dot => {
        const rect = dot.getBoundingClientRect();
        if (rect.width === 0 && rect.height === 0) return;
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        const dX = mouse.x - centerX;
        const dY = mouse.y - centerY;
        const dist = Math.sqrt(dX * dX + dY * dY);
        if (dist < minDist) {
            minDist = dist;
            nearestDot = dot;
        }
    });

    const tracerProximity = 30;
    const tracerMaxDist = 25;
    const isNearTracer = nearestDot && minDist < tracerProximity;

    if (isNearTracer) {
        const closeness = Math.min(1, Math.max(0, 1 - (minDist - tracerMaxDist) / (tracerProximity - tracerMaxDist)));

        const tracerBase = 1 + (closeness * 1.2);
        wantScaleX = tracerBase + stretch * 0.4;
        wantScaleY = tracerBase - (stretch * 0.15);

        wantRotation = velocityRotation;
        morphRadius = '50%';
        wantMixBlend = 1 - closeness;

        wantBorderStyle = closeness;
        wantBgAlpha = 1 - (closeness * 0.85);

    } else if (isHovering) {
        const deformFactor = 0.3;
        wantScaleX = targetScale + (stretch * deformFactor);
        wantScaleY = targetScale - (stretch * deformFactor * 0.25);

        wantRotation = velocity > 2 ? velocityRotation : 0;
        morphRadius = '50%';

        wantBorderStyle = 1;
        wantBgAlpha = 0.12;
        wantMixBlend = 1;

    } else {
        wantScaleX = velocityDeformX;
        wantScaleY = velocityDeformY;
        wantRotation = velocityRotation;
        morphRadius = '50%';
        wantBorderStyle = 0;
        wantBgAlpha = 1;
        wantMixBlend = 1;
    }
    const scaleDt = smoothDamp(0.22, deltaRatio);
    const rotDt = smoothDamp(0.4, deltaRatio);
    const styleDt = smoothDamp(0.1, deltaRatio);

    smoothScaleX += (wantScaleX - smoothScaleX) * scaleDt;
    smoothScaleY += (wantScaleY - smoothScaleY) * scaleDt;
    currentRotation = lerpAngle(currentRotation, wantRotation, rotDt);
    smoothBorderOpacity += (wantBorderStyle - smoothBorderOpacity) * styleDt;
    smoothBgAlpha += (wantBgAlpha - smoothBgAlpha) * styleDt;
    smoothMixBlend += (wantMixBlend - smoothMixBlend) * styleDt;
    const borderWeight = 1.5 + smoothBorderOpacity * 0.5;
    const borderAlpha = smoothBorderOpacity;
    const bgAlpha = smoothBgAlpha;

    let bgColor, border;
    if (borderAlpha > 0.01) {
        bgColor = `rgba(255, 255, 255, ${(bgAlpha * 0.95).toFixed(3)})`;
        border = `${borderWeight.toFixed(1)}px solid rgba(255, 255, 255, ${(0.6 + borderAlpha * 0.4).toFixed(3)})`;
    } else {
        bgColor = `rgba(255, 255, 255, ${bgAlpha.toFixed(3)})`;
        border = '0px solid transparent';
    }
    const mixBlend = smoothMixBlend > 0.5 ? 'difference' : 'normal';
    const zoomCompensation = baseDPR / window.devicePixelRatio;
    const size = BASE_SIZE * zoomCompensation;
    const half = size / 2;
    setX(pos.x - half);
    setY(pos.y - half);
    setWidth(size);
    setHeight(size);
    setScaleX(smoothScaleX);
    setScaleY(smoothScaleY);
    setRotation(currentRotation);
    setBorderRadius(morphRadius);
    setBgColor(bgColor);
    setBorder(border);
    setMixBlendMode(mixBlend);

    const dotSize = 4 * zoomCompensation;
    const dotHalf = dotSize / 2;
    setDotX(posDot.x - dotHalf);
    setDotY(posDot.y - dotHalf);
    setDotWidth(dotSize);
    setDotHeight(dotSize);
});

const observer = new MutationObserver(() => {
    attachInteractivity();
});
observer.observe(document.body, { childList: true, subtree: true });
