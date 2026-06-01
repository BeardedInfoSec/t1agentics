/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';
import './ThreatIntelShell.css';

function ThreatIntelTabs({ active, onNavigate, items }) {
  return (
    <div className="ti-tabs">
      {items.map((item) => (
        <button
          key={item.id}
          className={`ti-tab ${active === item.id ? 'active' : ''}`}
          onClick={() => onNavigate(item)}
          type="button"
          data-tour={`threat-intel-tab-${item.id}`}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

export default ThreatIntelTabs;
