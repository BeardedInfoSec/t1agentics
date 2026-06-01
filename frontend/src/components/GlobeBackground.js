/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useRef, useEffect, useCallback } from 'react';

/**
 * GlobeBackground - Animated dotted globe canvas
 *
 * Renders a slowly rotating wireframe globe made of dots.
 * Used as a subtle background element on the Dashboard.
 */
function GlobeBackground({ size = 550, opacity = 0.35 }) {
  const canvasRef = useRef(null);
  const animationRef = useRef(null);
  const angleRef = useRef(0);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;
    const radius = Math.min(cx, cy) * 0.85;

    ctx.clearRect(0, 0, w, h);

    const rotation = angleRef.current;
    const dotColor = getComputedStyle(document.documentElement)
      .getPropertyValue('--text-secondary')
      .trim() || '#6b7280';

    // Draw latitude lines as dots
    const latLines = 12;
    const lonLines = 24;
    const dotsPerLine = 60;

    for (let lat = 0; lat < latLines; lat++) {
      const phi = (Math.PI / latLines) * lat - Math.PI / 2;
      const y3d = Math.sin(phi);
      const rLat = Math.cos(phi);

      for (let d = 0; d < dotsPerLine; d++) {
        const theta = (2 * Math.PI / dotsPerLine) * d + rotation;
        const x3d = rLat * Math.cos(theta);
        const z3d = rLat * Math.sin(theta);

        // Only draw front-facing dots
        if (z3d < -0.1) continue;

        const depthFade = 0.3 + 0.7 * ((z3d + 1) / 2);
        const screenX = cx + x3d * radius;
        const screenY = cy + y3d * radius;
        const dotSize = 1 + depthFade * 1;

        ctx.beginPath();
        ctx.arc(screenX, screenY, dotSize, 0, Math.PI * 2);
        ctx.fillStyle = dotColor;
        ctx.globalAlpha = opacity * depthFade * 0.6;
        ctx.fill();
      }
    }

    // Draw longitude lines as dots
    for (let lon = 0; lon < lonLines; lon++) {
      const theta = (2 * Math.PI / lonLines) * lon + rotation;

      for (let d = 0; d < dotsPerLine; d++) {
        const phi = (Math.PI / dotsPerLine) * d - Math.PI / 2;
        const y3d = Math.sin(phi);
        const rLat = Math.cos(phi);
        const x3d = rLat * Math.cos(theta);
        const z3d = rLat * Math.sin(theta);

        if (z3d < -0.1) continue;

        const depthFade = 0.3 + 0.7 * ((z3d + 1) / 2);
        const screenX = cx + x3d * radius;
        const screenY = cy + y3d * radius;
        const dotSize = 1 + depthFade * 0.8;

        ctx.beginPath();
        ctx.arc(screenX, screenY, dotSize, 0, Math.PI * 2);
        ctx.fillStyle = dotColor;
        ctx.globalAlpha = opacity * depthFade * 0.4;
        ctx.fill();
      }
    }

    ctx.globalAlpha = 1;

    // Slow rotation
    angleRef.current += 0.002;
    animationRef.current = requestAnimationFrame(draw);
  }, [opacity]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    // Handle high-DPI displays
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    const ctx = canvas.getContext('2d');
    if (ctx) ctx.scale(dpr, dpr);

    // Respect reduced motion preference
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduced) {
      // Draw once without animation
      draw();
      return;
    }

    animationRef.current = requestAnimationFrame(draw);

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [size, draw]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        top: '50%',
        right: '-5%',
        transform: 'translateY(-50%)',
        pointerEvents: 'none',
        opacity: opacity,
        zIndex: 0,
      }}
      aria-hidden="true"
    />
  );
}

export default GlobeBackground;
