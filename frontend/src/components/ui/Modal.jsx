/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Modal Component
 * Accessible modal/dialog with focus trap and ARIA support
 */

import React, { useEffect, useRef, useCallback } from 'react';
import { createPortal } from 'react-dom';
import styles from './Modal.module.css';

const Modal = ({
  isOpen,
  onClose,
  title,
  children,
  size = 'md', // sm, md, lg, xl
  showCloseButton = true,
  closeOnOverlayClick = true,
  closeOnEscape = true,
  className = '',
}) => {
  const modalRef = useRef(null);
  const previousActiveElement = useRef(null);

  // Keep latest callbacks in refs so the focus-trap effect below does NOT list
  // them in its deps. Callers commonly pass an inline `onClose` (a fresh
  // function every render); if it were a dep, the effect would tear down and
  // re-run on every parent re-render, and its cleanup restores focus away from
  // the field being typed in — making typing in modal forms lose focus each
  // keystroke.
  const onCloseRef = useRef(onClose);
  const closeOnEscapeRef = useRef(closeOnEscape);
  onCloseRef.current = onClose;
  closeOnEscapeRef.current = closeOnEscape;

  // Get all focusable elements within the modal
  const getFocusableElements = useCallback(() => {
    if (!modalRef.current) return [];
    return modalRef.current.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
  }, []);

  // Focus trap and keyboard handling
  useEffect(() => {
    if (!isOpen) return;

    // Store the previously focused element
    previousActiveElement.current = document.activeElement;

    // Focus the modal container
    const timer = setTimeout(() => {
      modalRef.current?.focus();
    }, 0);

    const handleKeyDown = (e) => {
      // Close on Escape
      if (e.key === 'Escape' && closeOnEscapeRef.current) {
        e.preventDefault();
        onCloseRef.current();
        return;
      }

      // Focus trap on Tab
      if (e.key === 'Tab') {
        const focusableElements = getFocusableElements();
        if (focusableElements.length === 0) return;

        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (e.shiftKey) {
          // Shift + Tab: go backwards
          if (document.activeElement === firstElement || document.activeElement === modalRef.current) {
            e.preventDefault();
            lastElement.focus();
          }
        } else {
          // Tab: go forwards
          if (document.activeElement === lastElement) {
            e.preventDefault();
            firstElement.focus();
          }
        }
      }
    };

    // Prevent body scroll when modal is open
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      clearTimeout(timer);
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = originalOverflow;

      // Restore focus to the previously focused element
      previousActiveElement.current?.focus();
    };
  }, [isOpen, getFocusableElements]);

  // Handle overlay click
  const handleOverlayClick = (e) => {
    if (closeOnOverlayClick && e.target === e.currentTarget) {
      onClose();
    }
  };

  if (!isOpen) return null;

  const sizeClass = styles[`size${size.charAt(0).toUpperCase() + size.slice(1)}`] || styles.sizeMd;

  return createPortal(
    <div
      className={styles.overlay}
      onClick={handleOverlayClick}
      role="presentation"
    >
      <div
        ref={modalRef}
        className={`${styles.modal} ${sizeClass} ${className}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? 'modal-title' : undefined}
        tabIndex={-1}
      >
        {(title || showCloseButton) && (
          <header className={styles.header}>
            {title && (
              <h2 id="modal-title" className={styles.title}>
                {title}
              </h2>
            )}
            {showCloseButton && (
              <button
                type="button"
                className={styles.closeButton}
                onClick={onClose}
                aria-label="Close modal"
              >
                <span aria-hidden="true">&times;</span>
              </button>
            )}
          </header>
        )}
        <div className={styles.content}>
          {children}
        </div>
      </div>
    </div>,
    document.body
  );
};

// Sub-components for flexible composition
Modal.Header = ({ children, className = '' }) => (
  <div className={`${styles.customHeader} ${className}`}>{children}</div>
);

Modal.Body = ({ children, className = '' }) => (
  <div className={`${styles.body} ${className}`}>{children}</div>
);

Modal.Footer = ({ children, className = '' }) => (
  <div className={`${styles.footer} ${className}`}>{children}</div>
);

export default Modal;
