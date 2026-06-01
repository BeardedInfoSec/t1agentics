/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import { useEffect, useCallback, useRef, createContext, useContext, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

// Default global shortcuts configuration
const DEFAULT_SHORTCUTS = {
  // Navigation shortcuts
  'g+d': { action: 'navigate', path: '/dashboard', description: 'Go to Dashboard' },
  'g+q': { action: 'navigate', path: '/queue', description: 'Go to Security Queue' },
  'g+s': { action: 'navigate', path: '/search', description: 'Go to Global Search' },
  'g+t': { action: 'navigate', path: '/threat-intel', description: 'Go to Threat Intel' },
  'g+p': { action: 'navigate', path: '/playbooks', description: 'Go to Playbooks' },
  'g+i': { action: 'navigate', path: '/integrations', description: 'Go to Integrations' },
  'g+k': { action: 'navigate', path: '/knowledge-base', description: 'Go to Knowledge Base' },
  'g+a': { action: 'navigate', path: '/workbench/approvals', description: 'Go to Approvals' },
  'g+n': { action: 'navigate', path: '/investigate', description: 'New Investigation' },

  // Global actions
  '/': { action: 'focus', target: 'search', description: 'Focus search' },
  '?': { action: 'toggle', target: 'shortcutsHelp', description: 'Show keyboard shortcuts' },
  'Escape': { action: 'close', description: 'Close modal/panel' },

  // Theme toggle
  'ctrl+shift+l': { action: 'toggle', target: 'theme', description: 'Toggle light/dark theme' },
};

// Context for keyboard shortcuts
const KeyboardShortcutsContext = createContext(null);

/**
 * Parse a keyboard event into a normalized key string
 */
function getKeyString(event) {
  const parts = [];
  if (event.ctrlKey || event.metaKey) parts.push('ctrl');
  if (event.altKey) parts.push('alt');
  if (event.shiftKey) parts.push('shift');

  let key = event.key.toLowerCase();
  // Normalize special keys
  if (key === ' ') key = 'space';
  if (key === 'arrowup') key = 'up';
  if (key === 'arrowdown') key = 'down';
  if (key === 'arrowleft') key = 'left';
  if (key === 'arrowright') key = 'right';

  parts.push(key);
  return parts.join('+');
}

/**
 * Check if the current element should block shortcuts
 */
function shouldBlockShortcut(event) {
  const target = event.target;
  const tagName = target.tagName.toLowerCase();

  // Always allow Escape
  if (event.key === 'Escape') return false;

  // Block if typing in input, textarea, or contenteditable
  if (tagName === 'input' || tagName === 'textarea' || target.isContentEditable) {
    // Allow ctrl/cmd combinations in inputs
    if (event.ctrlKey || event.metaKey) return false;
    return true;
  }

  // Block in Monaco editor
  if (target.closest('.monaco-editor')) {
    return true;
  }

  return false;
}

export function KeyboardShortcutsProvider({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [showHelp, setShowHelp] = useState(false);
  const [shortcuts, setShortcuts] = useState(DEFAULT_SHORTCUTS);
  const customHandlers = useRef(new Map());
  const sequenceBuffer = useRef([]);
  const sequenceTimeout = useRef(null);

  // Register custom shortcut handler
  const registerShortcut = useCallback((key, handler, options = {}) => {
    customHandlers.current.set(key, { handler, options });
    if (options.description) {
      setShortcuts(prev => ({
        ...prev,
        [key]: { action: 'custom', description: options.description }
      }));
    }
    return () => {
      customHandlers.current.delete(key);
      setShortcuts(prev => {
        const next = { ...prev };
        delete next[key];
        return next;
      });
    };
  }, []);

  // Unregister shortcut
  const unregisterShortcut = useCallback((key) => {
    customHandlers.current.delete(key);
    setShortcuts(prev => {
      const next = { ...prev };
      delete next[key];
      return next;
    });
  }, []);

  // Execute shortcut action
  const executeAction = useCallback((shortcut) => {
    if (!shortcut) return false;

    switch (shortcut.action) {
      case 'navigate':
        if (location.pathname !== shortcut.path) {
          navigate(shortcut.path);
        }
        return true;

      case 'focus':
        if (shortcut.target === 'search') {
          const searchInput = document.querySelector('[data-shortcut-target="search"]') ||
                             document.querySelector('.global-search-input') ||
                             document.querySelector('input[type="search"]');
          if (searchInput) {
            searchInput.focus();
            searchInput.select();
          }
        }
        return true;

      case 'toggle':
        if (shortcut.target === 'shortcutsHelp') {
          setShowHelp(prev => !prev);
        } else if (shortcut.target === 'theme') {
          // Theme toggle handled via callback
          const event = new CustomEvent('toggleTheme');
          window.dispatchEvent(event);
        }
        return true;

      case 'close':
        setShowHelp(false);
        // Dispatch close event for modals
        const closeEvent = new CustomEvent('closeModal');
        window.dispatchEvent(closeEvent);
        return true;

      default:
        return false;
    }
  }, [navigate, location.pathname]);

  // Handle keyboard event
  const handleKeyDown = useCallback((event) => {
    if (shouldBlockShortcut(event)) return;

    const keyString = getKeyString(event);

    // Check for sequence shortcuts (e.g., g+d)
    if (keyString.length === 1 && /^[a-z]$/.test(keyString)) {
      // Clear previous timeout
      if (sequenceTimeout.current) {
        clearTimeout(sequenceTimeout.current);
      }

      // Add to buffer
      sequenceBuffer.current.push(keyString);

      // Check for sequence match
      if (sequenceBuffer.current.length >= 2) {
        const sequence = sequenceBuffer.current.join('+');
        const shortcut = shortcuts[sequence];

        if (shortcut) {
          event.preventDefault();

          // Check custom handlers first
          const customHandler = customHandlers.current.get(sequence);
          if (customHandler) {
            customHandler.handler(event);
          } else {
            executeAction(shortcut);
          }

          sequenceBuffer.current = [];
          return;
        }
      }

      // Set timeout to clear buffer
      sequenceTimeout.current = setTimeout(() => {
        sequenceBuffer.current = [];
      }, 500);

      return;
    }

    // Reset sequence buffer for non-letter keys
    sequenceBuffer.current = [];

    // Check for direct shortcut match
    const shortcut = shortcuts[keyString];

    // Check custom handlers first
    const customHandler = customHandlers.current.get(keyString);
    if (customHandler) {
      event.preventDefault();
      customHandler.handler(event);
      return;
    }

    if (shortcut) {
      event.preventDefault();
      executeAction(shortcut);
    }
  }, [shortcuts, executeAction]);

  // Set up global listener
  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      if (sequenceTimeout.current) {
        clearTimeout(sequenceTimeout.current);
      }
    };
  }, [handleKeyDown]);

  const value = {
    shortcuts,
    showHelp,
    setShowHelp,
    registerShortcut,
    unregisterShortcut,
  };

  return (
    <KeyboardShortcutsContext.Provider value={value}>
      {children}
      {showHelp && <KeyboardShortcutsHelp onClose={() => setShowHelp(false)} />}
    </KeyboardShortcutsContext.Provider>
  );
}

// Keyboard shortcuts help modal
function KeyboardShortcutsHelp({ onClose }) {
  const { shortcuts } = useKeyboardShortcuts();

  // Group shortcuts by category
  const groups = {
    'Navigation': [],
    'Actions': [],
    'Other': []
  };

  Object.entries(shortcuts).forEach(([key, config]) => {
    const item = { key, ...config };
    if (key.startsWith('g+')) {
      groups['Navigation'].push(item);
    } else if (['/', 'ctrl+shift+l'].includes(key)) {
      groups['Actions'].push(item);
    } else {
      groups['Other'].push(item);
    }
  });

  useEffect(() => {
    const handleEscape = (e) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [onClose]);

  return (
    <div className="keyboard-shortcuts-overlay" onClick={onClose}>
      <div className="keyboard-shortcuts-modal" onClick={e => e.stopPropagation()}>
        <div className="keyboard-shortcuts-header">
          <h2>Keyboard Shortcuts</h2>
          <button className="keyboard-shortcuts-close" onClick={onClose}>&times;</button>
        </div>
        <div className="keyboard-shortcuts-content">
          {Object.entries(groups).map(([group, items]) => (
            items.length > 0 && (
              <div key={group} className="keyboard-shortcuts-group">
                <h3>{group}</h3>
                <div className="keyboard-shortcuts-list">
                  {items.map(({ key, description }) => (
                    <div key={key} className="keyboard-shortcut-item">
                      <kbd className="keyboard-shortcut-key">
                        {formatShortcutKey(key)}
                      </kbd>
                      <span className="keyboard-shortcut-desc">{description}</span>
                    </div>
                  ))}
                </div>
              </div>
            )
          ))}
        </div>
        <div className="keyboard-shortcuts-footer">
          Press <kbd>?</kbd> to toggle this help
        </div>
      </div>
    </div>
  );
}

// Format shortcut key for display
function formatShortcutKey(key) {
  return key
    .split('+')
    .map(part => {
      if (part === 'ctrl') return 'Ctrl';
      if (part === 'alt') return 'Alt';
      if (part === 'shift') return 'Shift';
      if (part === 'escape') return 'Esc';
      return part.toUpperCase();
    })
    .join(' + ');
}

// Hook to use keyboard shortcuts
export function useKeyboardShortcuts() {
  const context = useContext(KeyboardShortcutsContext);
  if (!context) {
    throw new Error('useKeyboardShortcuts must be used within a KeyboardShortcutsProvider');
  }
  return context;
}

// Hook for registering component-specific shortcuts
export function useShortcut(key, handler, options = {}) {
  const { registerShortcut } = useKeyboardShortcuts();

  useEffect(() => {
    if (!key || !handler) return;
    return registerShortcut(key, handler, options);
  }, [key, handler, options, registerShortcut]);
}

export default useKeyboardShortcuts;
