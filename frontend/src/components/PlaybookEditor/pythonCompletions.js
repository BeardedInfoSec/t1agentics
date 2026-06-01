/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Python completions provider and code generator for PlaybookEditor Monaco editor.
 */

const SAFE_IMPORTS = [
  'json', 're', 'math', 'hashlib', 'base64', 'datetime', 'collections',
  'itertools', 'functools', 'operator', 'string', 'textwrap', 'difflib',
  'html', 'urllib.parse', 'ipaddress', 'uuid',
];

const ALERT_FIELDS = [
  'severity', 'title', 'description', 'source', 'destination',
  'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
  'alert_type', 'timestamp', 'raw', 'tags', 'indicators',
  'hostname', 'username', 'process_name', 'file_hash',
  'url', 'domain', 'email', 'action', 'status', 'category',
];

const PYTHON_BUILTINS = [
  'abs', 'all', 'any', 'bool', 'dict', 'enumerate', 'filter', 'float',
  'int', 'isinstance', 'len', 'list', 'map', 'max', 'min', 'print',
  'range', 'reversed', 'round', 'set', 'sorted', 'str', 'sum', 'tuple',
  'type', 'zip', 'hasattr', 'getattr', 'setattr',
];

/**
 * Register Python IntelliSense completions for Monaco.
 * Call once per Monaco instance (guard with a ref).
 */
export function registerPythonCompletions(monaco) {
  monaco.languages.registerCompletionItemProvider('python', {
    triggerCharacters: ["'", '"', '.', '['],
    provideCompletionItems: (model, position) => {
      const textUntilPosition = model.getValueInRange({
        startLineNumber: position.lineNumber,
        startColumn: 1,
        endLineNumber: position.lineNumber,
        endColumn: position.column,
      });

      const suggestions = [];

      // inputs['field'] completions
      if (/inputs\s*\[\s*['"]$/.test(textUntilPosition)) {
        ALERT_FIELDS.forEach((field) => {
          suggestions.push({
            label: field,
            kind: monaco.languages.CompletionItemKind.Field,
            insertText: field,
            documentation: `Alert field: ${field}`,
          });
        });
        return { suggestions };
      }

      // inputs.get(' completions
      if (/inputs\.get\(\s*['"]$/.test(textUntilPosition)) {
        ALERT_FIELDS.forEach((field) => {
          suggestions.push({
            label: field,
            kind: monaco.languages.CompletionItemKind.Field,
            insertText: field,
            documentation: `Alert field: ${field}`,
          });
        });
        return { suggestions };
      }

      // import completions
      if (/^\s*import\s+\w*$/.test(textUntilPosition) || /^\s*from\s+\w*$/.test(textUntilPosition)) {
        SAFE_IMPORTS.forEach((mod) => {
          suggestions.push({
            label: mod,
            kind: monaco.languages.CompletionItemKind.Module,
            insertText: mod,
            documentation: `Safe import: ${mod}`,
          });
        });
        return { suggestions };
      }

      // Code template snippets
      suggestions.push({
        label: 'def main',
        kind: monaco.languages.CompletionItemKind.Snippet,
        insertText: 'def main(inputs):\n    \n    return {"result": None}',
        insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
        documentation: 'Basic main function template',
      });

      suggestions.push({
        label: 'def main (alert processing)',
        kind: monaco.languages.CompletionItemKind.Snippet,
        insertText: [
          'def main(inputs):',
          '    severity = inputs.get("severity", "unknown")',
          '    title = inputs.get("title", "")',
          '    ',
          '    return {"result": None, "severity": severity}',
        ].join('\n'),
        insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
        documentation: 'Alert processing template with severity and title',
      });

      suggestions.push({
        label: 'def main (IOC extraction)',
        kind: monaco.languages.CompletionItemKind.Snippet,
        insertText: [
          'import re',
          'import ipaddress',
          '',
          'def main(inputs):',
          '    text = inputs.get("raw", "")',
          '    ips = re.findall(r"\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b", text)',
          '    valid = [ip for ip in ips if ipaddress.ip_address(ip)]',
          '    return {"iocs": valid}',
        ].join('\n'),
        insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
        documentation: 'IOC extraction template with IP regex',
      });

      // Safe import suggestions
      SAFE_IMPORTS.forEach((mod) => {
        suggestions.push({
          label: `import ${mod}`,
          kind: monaco.languages.CompletionItemKind.Module,
          insertText: `import ${mod}`,
          documentation: `Import ${mod} (sandbox-allowed)`,
        });
      });

      // Python builtins
      PYTHON_BUILTINS.forEach((fn) => {
        suggestions.push({
          label: fn,
          kind: monaco.languages.CompletionItemKind.Function,
          insertText: fn,
          documentation: `Python builtin: ${fn}`,
        });
      });

      // inputs variable
      suggestions.push({
        label: 'inputs',
        kind: monaco.languages.CompletionItemKind.Variable,
        insertText: 'inputs',
        documentation: 'Dictionary of resolved input values',
      });

      return { suggestions };
    },
  });
}

/**
 * Sanitize a string into a valid Python identifier.
 */
function toPythonName(str) {
  if (!str) return 'main';
  const cleaned = str
    .toLowerCase()
    .replace(/[^a-z0-9_\s]/g, '')
    .replace(/\s+/g, '_')
    .replace(/^[0-9]+/, '')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '');
  return cleaned || 'main';
}

/**
 * Check if a value looks like a data path (dynamic).
 */
export function isDynamicValue(val) {
  return typeof val === 'string' && val.startsWith('$.');
}

/**
 * Build input extraction lines for the given entries.
 */
function buildInputLines(inputs) {
  const validInputs = (inputs || []).filter((e) => e.key && e.key.trim());
  return validInputs.map((entry) => {
    const key = entry.key.trim();
    const val = entry.value || '';
    if (isDynamicValue(val)) {
      return `    ${key} = inputs['${key}']  # ${val}`;
    } else if (val) {
      return `    ${key} = inputs['${key}']  # static: ${val}`;
    }
    return `    ${key} = inputs['${key}']`;
  });
}

/**
 * Generate a fresh Python code template from an array of input entries.
 *
 * @param {Array<{key: string, value?: string}>} inputs
 * @param {string} [functionName] - function name (defaults to 'main')
 * @returns {string} Python code
 */
export function generateCodeFromInputs(inputs, functionName) {
  const fnName = toPythonName(functionName);
  const extractionLines = buildInputLines(inputs);

  if (extractionLines.length === 0) {
    return `def ${fnName}(inputs):\n    \n    return {"result": None}\n`;
  }

  const lines = [`def ${fnName}(inputs):`];
  lines.push(...extractionLines);
  lines.push('');
  lines.push('    # Your code here');
  lines.push('');
  lines.push('    return {"result": None}');
  lines.push('');

  return lines.join('\n');
}

/**
 * Update existing user code by replacing the def line and input extraction block,
 * while preserving any user-written code below.
 *
 * @param {string} existingCode - current code in the editor
 * @param {Array<{key: string, value?: string}>} inputs
 * @param {string} [functionName]
 * @returns {string} updated code
 */
export function updateCodeWithInputs(existingCode, inputs, functionName) {
  const fnName = toPythonName(functionName);
  const extractionLines = buildInputLines(inputs);

  if (!existingCode || !existingCode.trim()) {
    return generateCodeFromInputs(inputs, functionName);
  }

  const lines = existingCode.split('\n');

  // Find the def line
  const defIdx = lines.findIndex((l) => /^\s*def\s+\w+\s*\(/.test(l));
  if (defIdx === -1) {
    // No def found - prepend def + extractions to existing code
    const header = [`def ${fnName}(inputs):`];
    header.push(...extractionLines);
    if (extractionLines.length > 0) header.push('');
    return header.join('\n') + '\n' + existingCode;
  }

  // Find where the extraction block ends (lines that match `    var = inputs['var']`)
  let blockEnd = defIdx + 1;
  while (blockEnd < lines.length) {
    const line = lines[blockEnd];
    // extraction lines: `    key = inputs['key']`
    if (/^\s+\w+\s*=\s*inputs\[/.test(line)) {
      blockEnd++;
      continue;
    }
    // skip blank lines within the extraction block
    if (line.trim() === '' && blockEnd === defIdx + 1 + extractionLines.length) {
      blockEnd++;
      continue;
    }
    if (line.trim() === '' && blockEnd < defIdx + 1 + extractionLines.length + 2) {
      blockEnd++;
      continue;
    }
    break;
  }

  // Build new code: lines before def + new def + extractions + user code after block
  const before = lines.slice(0, defIdx);
  const after = lines.slice(blockEnd);
  const newDef = [`def ${fnName}(inputs):`];
  newDef.push(...extractionLines);
  if (extractionLines.length > 0 && after.length > 0 && after[0].trim() !== '') {
    newDef.push('');
  }

  return [...before, ...newDef, ...after].join('\n');
}
