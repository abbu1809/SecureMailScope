import React, { useEffect, useRef } from 'react';
import { animate, stagger } from 'animejs';

export const BackgroundAnimation: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // 1. Pulse glowing connection nodes
    const nodePulse = animate('.mesh-node-glow', {
      scale: [1, 1.4, 1],
      opacity: [0.35, 0.9, 0.35],
      duration: 3200,
      ease: 'inOutQuad',
      delay: stagger(200, { from: 'center' }),
      loop: true,
    });

    // 2. Handshake packet data flow along conduits
    const pathAnimation = animate('.handshake-stream', {
      strokeDashoffset: [800, 0],
      duration: 4800,
      ease: 'inOutSine',
      delay: stagger(350),
      alternate: true,
      loop: true,
    });

    // 3. Rotating concentric cryptographic rings
    const ringRotate = animate('.crypto-concentric-ring', {
      rotate: '360deg',
      duration: 36000,
      ease: 'linear',
      loop: true,
    });

    const reverseRing = animate('.crypto-concentric-reverse', {
      rotate: '-360deg',
      duration: 44000,
      ease: 'linear',
      loop: true,
    });

    // 4. Subtle drifting data particles
    const particleDrift = animate('.data-particle', {
      translateY: () => (Math.random() - 0.5) * 35,
      translateX: () => (Math.random() - 0.5) * 35,
      duration: 4500,
      ease: 'inOutQuad',
      alternate: true,
      loop: true,
      delay: stagger(100),
    });

    return () => {
      try {
        nodePulse.pause();
        pathAnimation.pause();
        ringRotate.pause();
        reverseRing.pause();
        particleDrift.pause();
      } catch (e) {
        // cleanup safe
      }
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className="absolute inset-0 pointer-events-none overflow-hidden z-0 select-none"
      style={{ opacity: 0.30 }}
      aria-hidden="true"
    >
      <style>{`
        @keyframes radarExpand {
          0% { r: 16px; opacity: 0.8; stroke-width: 2px; }
          100% { r: 180px; opacity: 0; stroke-width: 0.5px; }
        }
        @keyframes laserBeam {
          0% { stroke-dashoffset: 600; }
          100% { stroke-dashoffset: 0; }
        }
        .radar-wave-1 { animation: radarExpand 4s cubic-bezier(0.1, 0.8, 0.3, 1) infinite; }
        .radar-wave-2 { animation: radarExpand 4s cubic-bezier(0.1, 0.8, 0.3, 1) 1.3s infinite; }
        .radar-wave-3 { animation: radarExpand 4s cubic-bezier(0.1, 0.8, 0.3, 1) 2.6s infinite; }
        .beam-flow { stroke-dasharray: 80 320; animation: laserBeam 4s linear infinite; }
      `}</style>

      <svg
        className="w-full h-full min-h-[950px]"
        viewBox="0 0 1440 950"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        preserveAspectRatio="xMidYMid slice"
      >
        <defs>
          {/* Linear Gradients */}
          <linearGradient id="beam-blue" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#0066ff" stopOpacity="0" />
            <stop offset="50%" stopColor="#0066ff" stopOpacity="1" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
          </linearGradient>

          <linearGradient id="beam-green" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#16a34a" stopOpacity="0" />
            <stop offset="50%" stopColor="#16a34a" stopOpacity="1" />
            <stop offset="100%" stopColor="#4ade80" stopOpacity="0" />
          </linearGradient>

          <linearGradient id="conduit-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#e0e0e0" stopOpacity="0.4" />
            <stop offset="35%" stopColor="#0066ff" stopOpacity="0.5" />
            <stop offset="65%" stopColor="#141414" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#e0e0e0" stopOpacity="0.4" />
          </linearGradient>

          {/* Radial Ambient Glows */}
          <radialGradient id="hub-glow-blue" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#0066ff" stopOpacity="0.22" />
            <stop offset="70%" stopColor="#0066ff" stopOpacity="0.03" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
          </radialGradient>

          <radialGradient id="hub-glow-green" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#16a34a" stopOpacity="0.18" />
            <stop offset="70%" stopColor="#16a34a" stopOpacity="0.02" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* ─── 1. AMBIENT RADIAL LIGHTING ───────────────────────────────────── */}
        <circle cx="200" cy="280" r="320" fill="url(#hub-glow-blue)" />
        <circle cx="1240" cy="300" r="340" fill="url(#hub-glow-green)" />
        <circle cx="720" cy="420" r="420" fill="url(#hub-glow-blue)" />

        {/* ─── 2. RADAR SCANNING ARCS ───────────────────────────────────────── */}
        <g transform="translate(180, 240)">
          <circle className="radar-wave-1" cx="0" cy="0" r="20" stroke="#0066ff" fill="none" />
          <circle className="radar-wave-2" cx="0" cy="0" r="20" stroke="#0066ff" fill="none" />
          <circle className="radar-wave-3" cx="0" cy="0" r="20" stroke="#0066ff" fill="none" />
        </g>
        <g transform="translate(1260, 260)">
          <circle className="radar-wave-1" cx="0" cy="0" r="20" stroke="#16a34a" fill="none" />
          <circle className="radar-wave-2" cx="0" cy="0" r="20" stroke="#16a34a" fill="none" />
          <circle className="radar-wave-3" cx="0" cy="0" r="20" stroke="#16a34a" fill="none" />
        </g>

        {/* ─── 3. ROTATING CONCENTRIC CIPHER RINGS (Center Ground) ──────────── */}
        <g className="crypto-concentric-ring" style={{ transformOrigin: '720px 420px' }}>
          <circle cx="720" cy="420" r="340" stroke="#e0e0e0" strokeWidth="1.2" strokeDasharray="8 14" fill="none" />
          <circle cx="720" cy="420" r="260" stroke="#0066ff" strokeWidth="1" strokeDasharray="5 18" strokeOpacity="0.35" fill="none" />
          <rect x="713" y="78" width="14" height="14" rx="4" fill="#0066ff" opacity="0.6" />
          <rect x="713" y="750" width="14" height="14" rx="4" fill="#141414" opacity="0.5" />
        </g>

        <g className="crypto-concentric-reverse" style={{ transformOrigin: '720px 420px' }}>
          <polygon
            points="720,240 880,330 880,510 720,600 560,510 560,330"
            stroke="#141414"
            strokeWidth="1.2"
            strokeDasharray="6 12"
            strokeOpacity="0.2"
            fill="none"
          />
          <circle cx="720" cy="420" r="180" stroke="#0066ff" strokeWidth="1.4" strokeDasharray="10 16" strokeOpacity="0.25" fill="none" />
        </g>

        {/* ─── 4. INTERCONNECTING NETWORK CONDUITS ───────────────────────────── */}
        <g stroke="url(#conduit-grad)" strokeWidth="1.5" fill="none">
          <path className="handshake-stream" d="M 180 240 C 360 160, 520 480, 720 420" strokeDasharray="450" />
          <path className="handshake-stream" d="M 720 420 C 920 340, 1080 520, 1260 260" strokeDasharray="450" />
          <path className="handshake-stream" d="M 280 660 C 460 540, 580 320, 720 420" strokeDasharray="400" />
          <path className="handshake-stream" d="M 720 420 C 890 470, 1060 680, 1200 580" strokeDasharray="400" />
          <path d="M 200 420 C 500 750, 940 750, 1240 420" strokeDasharray="8 12" strokeWidth="1.2" strokeOpacity="0.25" />
        </g>

        {/* ─── 5. HIGH-SPEED ANIMATED PACKET PULSES ─────────────────────────── */}
        <g fill="none">
          <path className="beam-flow" d="M 180 240 C 360 160, 520 480, 720 420" stroke="url(#beam-blue)" strokeWidth="3" strokeLinecap="round" />
          <path className="beam-flow" d="M 720 420 C 920 340, 1080 520, 1260 260" stroke="url(#beam-green)" strokeWidth="3" strokeLinecap="round" />
          <path className="beam-flow" d="M 280 660 C 460 540, 580 320, 720 420" stroke="url(#beam-blue)" strokeWidth="2.5" strokeLinecap="round" />
          <path className="beam-flow" d="M 720 420 C 890 470, 1060 680, 1200 580" stroke="url(#beam-green)" strokeWidth="2.5" strokeLinecap="round" />
        </g>

        {/* ─── 6. SECURITY MESH NODES ───────────────────────────────────────── */}
        <g>
          {/* Center: Core SCoRE Engine */}
          <g transform="translate(720, 420)">
            <circle className="mesh-node-glow" r="28" fill="#0066ff" fillOpacity="0.1" />
            <circle className="mesh-node-glow" r="16" fill="#0066ff" fillOpacity="0.2" />
            <circle r="8" fill="#141414" />
            <circle r="4" fill="#ffffff" />
          </g>

          {/* Left Gateway Node */}
          <g transform="translate(180, 240)">
            <circle className="mesh-node-glow" r="20" fill="#0066ff" fillOpacity="0.15" />
            <circle r="7" fill="#0066ff" />
            <circle r="3" fill="#ffffff" />
          </g>

          {/* Right Gateway Node */}
          <g transform="translate(1260, 260)">
            <circle className="mesh-node-glow" r="20" fill="#16a34a" fillOpacity="0.15" />
            <circle r="7" fill="#16a34a" />
            <circle r="3" fill="#ffffff" />
          </g>

          {/* Lower Left Node */}
          <g transform="translate(280, 660)">
            <circle className="mesh-node-glow" r="16" fill="#141414" fillOpacity="0.1" />
            <circle r="5" fill="#141414" />
            <circle r="2" fill="#ffffff" />
          </g>

          {/* Lower Right Node */}
          <g transform="translate(1200, 580)">
            <circle className="mesh-node-glow" r="16" fill="#0066ff" fillOpacity="0.12" />
            <circle r="5" fill="#0066ff" />
            <circle r="2" fill="#ffffff" />
          </g>
        </g>

        {/* ─── 7. DRIFTING PACKET PARTICLES ─────────────────────────────────── */}
        <g fill="#0066ff">
          <circle className="data-particle" cx="340" cy="240" r="2.5" opacity="0.5" />
          <circle className="data-particle" cx="460" cy="330" r="3" opacity="0.6" />
          <circle className="data-particle" cx="620" cy="390" r="2" opacity="0.4" />
          <circle className="data-particle" cx="830" cy="390" r="3" opacity="0.6" />
          <circle className="data-particle" cx="1020" cy="360" r="2.5" opacity="0.5" />
          <circle className="data-particle" cx="1160" cy="280" r="2" opacity="0.4" />
          <circle className="data-particle" cx="390" cy="580" r="2.5" opacity="0.5" />
          <circle className="data-particle" cx="720" cy="660" r="2" opacity="0.4" />
          <circle className="data-particle" cx="1050" cy="520" r="2.5" opacity="0.5" />
        </g>

        {/* Subtle Watermarks */}
        <g fill="#707070" opacity="0.18" fontSize="9" fontFamily="monospace" fontWeight="600">
          <text x="80" y="520">250-STARTTLS // RFC 8314</text>
          <text x="80" y="540">PORT 587 / 465 / 993</text>
          <text x="1230" y="160">TLS 1.3 // AES-GCM</text>
          <text x="1230" y="180">NIST SP 800-52r2</text>
          <text x="640" y="800">SCoRE §4.1: DP + Blend - AB - UB</text>
        </g>
      </svg>
    </div>
  );
};
