import React from 'react';
import { isRedacted } from '../lib/http';

export const MAX_LINES = 5000;

/** Wraps any daemon redaction markers in a value so they read as changed by DropSuite. */
export function withRedactions(value: string): React.ReactNode {
  if (!isRedacted(value)) return value;
  const parts = value.split(/(\[REDACTED[^\]]*\])/g);
  return parts.map((p, i) =>
    /^\[REDACTED/.test(p) ? (
      <span key={i} className="redact" title="Redacted by DropSuite before storage">
        {p}
      </span>
    ) : (
      p
    ),
  );
}

/** Numbered, wrapping lines. Content is always rendered as text, never as markup. */
export const Lines: React.FC<{ lines: React.ReactNode[] }> = ({ lines }) => (
  <div className="code">
    {lines.map((l, i) => (
      <div className="ln" data-n={i + 1} key={i}>
        <span>{l === '' ? '\u200b' : l}</span>
      </div>
    ))}
  </div>
);

const JSON_TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b|([{}[\],])/g;

/** Pretty-printed JSON split into highlighted lines. */
export function jsonLines(value: unknown): React.ReactNode[] {
  const text = JSON.stringify(value, null, 2) ?? '';
  return text.split('\n').slice(0, MAX_LINES).map((line, li) => {
    const out: React.ReactNode[] = [];
    let last = 0;
    let m: RegExpExecArray | null;
    JSON_TOKEN.lastIndex = 0;
    let k = 0;
    while ((m = JSON_TOKEN.exec(line))) {
      if (m.index > last) out.push(line.slice(last, m.index));
      if (m[1] !== undefined) {
        if (m[2] !== undefined) {
          out.push(
            <span key={k++} className="k">
              {m[1]}
            </span>,
            <span key={k++} className="p">
              {m[2]}
            </span>,
          );
        } else {
          out.push(
            <span key={k++} className="s">
              {withRedactions(m[1])}
            </span>,
          );
        }
      } else if (m[3] !== undefined) {
        out.push(
          <span key={k++} className="n">
            {m[3]}
          </span>,
        );
      } else if (m[4] !== undefined) {
        out.push(
          <span key={k++} className="l">
            {m[4]}
          </span>,
        );
      } else if (m[5] !== undefined) {
        out.push(
          <span key={k++} className="p">
            {m[5]}
          </span>,
        );
      }
      last = m.index + m[0].length;
    }
    if (last < line.length) out.push(line.slice(last));
    return <React.Fragment key={li}>{out}</React.Fragment>;
  });
}

export const HEX_LIMIT = 16 * 1024;

export function hexRows(bytes: Uint8Array): { off: string; hex: string; ascii: string }[] {
  const rows = [];
  const n = Math.min(bytes.length, HEX_LIMIT);
  for (let i = 0; i < n; i += 16) {
    const chunk = bytes.subarray(i, Math.min(i + 16, n));
    let hex = '';
    let ascii = '';
    for (let j = 0; j < 16; j++) {
      if (j < chunk.length) {
        hex += chunk[j].toString(16).padStart(2, '0') + (j === 7 ? '  ' : ' ');
        ascii += chunk[j] >= 32 && chunk[j] < 127 ? String.fromCharCode(chunk[j]) : '·';
      } else {
        hex += j === 7 ? '    ' : '   ';
      }
    }
    rows.push({ off: i.toString(16).padStart(8, '0'), hex, ascii });
  }
  return rows;
}

export const HexView: React.FC<{ bytes: Uint8Array }> = ({ bytes }) => {
  const rows = hexRows(bytes);
  return (
    <>
      {bytes.length > HEX_LIMIT && (
        <div className="hex-note">
          Showing the first {HEX_LIMIT / 1024} KB of {bytes.length.toLocaleString()} bytes. Copy exports the same range.
        </div>
      )}
      <div className="hex">
        {rows.map((r) => (
          <div className="row" key={r.off}>
            <span className="off">{r.off}</span>
            <span>{r.hex}</span>
            <span className="ascii">{r.ascii}</span>
          </div>
        ))}
      </div>
    </>
  );
};
