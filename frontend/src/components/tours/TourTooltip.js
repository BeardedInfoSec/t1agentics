/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useEffect, useRef } from 'react';
import RiggsAvatar from '../onboarding/RiggsAvatar';

/**
 * ARROW_SIZE - Half-width of the directional arrow in pixels.
 * Used for both the arrow CSS dimensions and offset calculations.
 */
const ARROW_SIZE = 8;

/**
 * GAP - Pixel gap between the target element and the tooltip edge.
 */
const GAP = 12;

/**
 * getTooltipPosition - Calculates absolute page position and arrow style
 * for the tooltip based on target element rect and desired placement.
 *
 * @param {DOMRect} targetRect - getBoundingClientRect() of the target element
 * @param {string} placement - One of 'top', 'bottom', 'left', 'right'
 * @param {DOMRect} tooltipRect - getBoundingClientRect() of the tooltip itself
 * @returns {{ tooltipStyle: object, arrowStyle: object }}
 */
function getTooltipPosition(targetRect, placement, tooltipRect) {
  const scrollX = window.scrollX || window.pageXOffset;
  const scrollY = window.scrollY || window.pageYOffset;

  let top = 0;
  let left = 0;
  const arrowStyle = {
    position: 'absolute',
    width: 0,
    height: 0,
    borderStyle: 'solid',
  };

  const tooltipWidth = tooltipRect?.width || 320;
  const tooltipHeight = tooltipRect?.height || 180;

  switch (placement) {
    case 'top':
      top = targetRect.top + scrollY - tooltipHeight - GAP;
      left = targetRect.left + scrollX + targetRect.width / 2 - tooltipWidth / 2;
      arrowStyle.bottom = -ARROW_SIZE;
      arrowStyle.left = '50%';
      arrowStyle.transform = 'translateX(-50%)';
      arrowStyle.borderWidth = `${ARROW_SIZE}px ${ARROW_SIZE}px 0 ${ARROW_SIZE}px`;
      arrowStyle.borderColor = 'var(--border-color) transparent transparent transparent';
      break;

    case 'bottom':
      top = targetRect.bottom + scrollY + GAP;
      left = targetRect.left + scrollX + targetRect.width / 2 - tooltipWidth / 2;
      arrowStyle.top = -ARROW_SIZE;
      arrowStyle.left = '50%';
      arrowStyle.transform = 'translateX(-50%)';
      arrowStyle.borderWidth = `0 ${ARROW_SIZE}px ${ARROW_SIZE}px ${ARROW_SIZE}px`;
      arrowStyle.borderColor = 'transparent transparent var(--border-color) transparent';
      break;

    case 'left':
      top = targetRect.top + scrollY + targetRect.height / 2 - tooltipHeight / 2;
      left = targetRect.left + scrollX - tooltipWidth - GAP;
      arrowStyle.right = -ARROW_SIZE;
      arrowStyle.top = '50%';
      arrowStyle.transform = 'translateY(-50%)';
      arrowStyle.borderWidth = `${ARROW_SIZE}px 0 ${ARROW_SIZE}px ${ARROW_SIZE}px`;
      arrowStyle.borderColor = 'transparent transparent transparent var(--border-color)';
      break;

    case 'right':
      top = targetRect.top + scrollY + targetRect.height / 2 - tooltipHeight / 2;
      left = targetRect.right + scrollX + GAP;
      arrowStyle.left = -ARROW_SIZE;
      arrowStyle.top = '50%';
      arrowStyle.transform = 'translateY(-50%)';
      arrowStyle.borderWidth = `${ARROW_SIZE}px ${ARROW_SIZE}px ${ARROW_SIZE}px 0`;
      arrowStyle.borderColor = 'transparent var(--border-color) transparent transparent';
      break;

    default:
      // Default to bottom
      top = targetRect.bottom + scrollY + GAP;
      left = targetRect.left + scrollX + targetRect.width / 2 - tooltipWidth / 2;
      arrowStyle.top = -ARROW_SIZE;
      arrowStyle.left = '50%';
      arrowStyle.transform = 'translateX(-50%)';
      arrowStyle.borderWidth = `0 ${ARROW_SIZE}px ${ARROW_SIZE}px ${ARROW_SIZE}px`;
      arrowStyle.borderColor = 'transparent transparent var(--border-color) transparent';
      break;
  }

  // Clamp to viewport edges with padding
  const viewportPadding = 16;
  if (left < viewportPadding) left = viewportPadding;
  if (left + tooltipWidth > window.innerWidth - viewportPadding) {
    left = window.innerWidth - tooltipWidth - viewportPadding;
  }
  if (top < viewportPadding + scrollY) top = viewportPadding + scrollY;

  return {
    tooltipStyle: { top, left },
    arrowStyle,
  };
}

/**
 * TourTooltip - Renders a positioned tooltip for a feature tour step.
 *
 * Displays a dark card with the Riggs AI avatar, step title/content,
 * step progress indicator, and navigation controls (Back, Next/Done, Skip).
 * The tooltip is absolutely positioned on the page based on the target
 * element's bounding rect and the requested placement direction.
 *
 * @param {object} props
 * @param {string} props.title - Step heading
 * @param {string} props.content - Step description text
 * @param {string} props.placement - 'top' | 'bottom' | 'left' | 'right'
 * @param {number} props.stepIndex - Zero-based current step index
 * @param {number} props.totalSteps - Total number of steps in the tour
 * @param {function} props.onNext - Called when user clicks Next
 * @param {function} props.onBack - Called when user clicks Back
 * @param {function} props.onSkip - Called when user clicks Skip
 * @param {function} props.onDone - Called when user clicks Done (last step)
 * @param {DOMRect} props.targetRect - getBoundingClientRect() of the target element
 */
export default function TourTooltip({
  title,
  content,
  placement = 'bottom',
  stepIndex = 0,
  totalSteps = 1,
  onNext,
  onBack,
  onSkip,
  onDone,
  targetRect,
}) {
  const tooltipRef = useRef(null);
  const [position, setPosition] = React.useState({ tooltipStyle: {}, arrowStyle: {} });

  // Recalculate position when target or placement changes
  useEffect(() => {
    if (!targetRect) return;

    const recalc = () => {
      const tooltipRect = tooltipRef.current?.getBoundingClientRect();
      const pos = getTooltipPosition(targetRect, placement, tooltipRect);
      setPosition(pos);
    };

    // Initial calculation
    recalc();

    // Recalculate after a frame so tooltip dimensions are known
    const rafId = requestAnimationFrame(recalc);
    return () => cancelAnimationFrame(rafId);
  }, [targetRect, placement]);

  if (!targetRect) return null;

  const isFirst = stepIndex === 0;
  const isLast = stepIndex === totalSteps - 1;

  // -- Inline styles (positioned absolutely on page) --

  const overlayStyle = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    zIndex: 9999,
    pointerEvents: 'none',
  };

  const cardStyle = {
    position: 'absolute',
    zIndex: 10000,
    width: 320,
    maxWidth: 'calc(100vw - 32px)',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: 10,
    padding: '16px 20px',
    boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
    color: 'var(--text-primary)',
    fontFamily: 'inherit',
    pointerEvents: 'auto',
    ...position.tooltipStyle,
  };

  const headerStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    marginBottom: 8,
  };

  const titleStyle = {
    fontSize: 15,
    fontWeight: 600,
    color: 'var(--text-primary)',
    margin: 0,
    lineHeight: 1.3,
  };

  const contentStyle = {
    fontSize: 13,
    lineHeight: 1.55,
    color: 'var(--text-secondary)',
    margin: '0 0 14px 0',
  };

  const footerStyle = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  };

  const stepIndicatorStyle = {
    fontSize: 11,
    color: 'var(--text-secondary)',
    fontWeight: 500,
    letterSpacing: '0.02em',
  };

  const buttonGroupStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
  };

  const baseButtonStyle = {
    padding: '5px 14px',
    fontSize: 12,
    fontWeight: 500,
    borderRadius: 6,
    cursor: 'pointer',
    border: 'none',
    transition: 'background 0.15s, opacity 0.15s',
    lineHeight: 1.4,
  };

  const skipButtonStyle = {
    ...baseButtonStyle,
    background: 'transparent',
    color: 'var(--text-secondary)',
    padding: '5px 8px',
  };

  const backButtonStyle = {
    ...baseButtonStyle,
    background: 'var(--bg-tertiary, rgba(255,255,255,0.06))',
    color: 'var(--text-secondary)',
    border: '1px solid var(--border-color)',
  };

  const primaryButtonStyle = {
    ...baseButtonStyle,
    background: 'var(--accent)',
    color: '#fff',
  };

  return (
    <>
      {/* Transparent overlay to capture context but not block target */}
      <div style={overlayStyle} />

      {/* Tooltip card */}
      <div ref={tooltipRef} style={cardStyle} role="dialog" aria-label={`Tour step ${stepIndex + 1} of ${totalSteps}`}>
        {/* Arrow */}
        <div style={position.arrowStyle} />

        {/* Header with Riggs avatar and title */}
        <div style={headerStyle}>
          <RiggsAvatar size={28} />
          <h4 style={titleStyle}>{title}</h4>
        </div>

        {/* Step content */}
        <p style={contentStyle}>{content}</p>

        {/* Footer: step indicator and navigation */}
        <div style={footerStyle}>
          <span style={stepIndicatorStyle}>
            Step {stepIndex + 1} of {totalSteps}
          </span>

          <div style={buttonGroupStyle}>
            <button
              style={skipButtonStyle}
              onClick={onSkip}
              onMouseOver={(e) => { e.currentTarget.style.opacity = '0.8'; }}
              onMouseOut={(e) => { e.currentTarget.style.opacity = '1'; }}
              type="button"
            >
              Skip
            </button>

            {!isFirst && (
              <button
                style={backButtonStyle}
                onClick={onBack}
                onMouseOver={(e) => { e.currentTarget.style.opacity = '0.85'; }}
                onMouseOut={(e) => { e.currentTarget.style.opacity = '1'; }}
                type="button"
              >
                Back
              </button>
            )}

            {isLast ? (
              <button
                style={primaryButtonStyle}
                onClick={onDone}
                onMouseOver={(e) => { e.currentTarget.style.opacity = '0.9'; }}
                onMouseOut={(e) => { e.currentTarget.style.opacity = '1'; }}
                type="button"
              >
                Done
              </button>
            ) : (
              <button
                style={primaryButtonStyle}
                onClick={onNext}
                onMouseOver={(e) => { e.currentTarget.style.opacity = '0.9'; }}
                onMouseOut={(e) => { e.currentTarget.style.opacity = '1'; }}
                type="button"
              >
                Next
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
