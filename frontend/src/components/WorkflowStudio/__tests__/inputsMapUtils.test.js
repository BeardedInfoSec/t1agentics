/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import { normalizeInputsEntries, entriesToInputObject } from '../inputsMapUtils';

describe('inputsMapUtils', () => {
  test('normalizeInputsEntries handles JSON strings', () => {
    const entries = normalizeInputsEntries('{"alert": "$.trigger.alert"}');
    expect(entries).toEqual([{ key: 'alert', path: '$.trigger.alert' }]);
  });

  test('normalizeInputsEntries handles objects', () => {
    const entries = normalizeInputsEntries({ alert: '$.trigger.alert', score: '$.nodes.score' });
    expect(entries).toEqual([
      { key: 'alert', path: '$.trigger.alert' },
      { key: 'score', path: '$.nodes.score' },
    ]);
  });

  test('entriesToInputObject filters empty keys', () => {
    const obj = entriesToInputObject([
      { key: 'alert', path: '$.trigger.alert' },
      { key: '', path: '$.ignored' },
    ]);
    expect(obj).toEqual({ alert: '$.trigger.alert' });
  });
});
