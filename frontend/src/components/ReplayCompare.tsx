import React, { useMemo, useState } from 'react';
import { ReplayResponse } from '../types';
import { bytesToText, dechunk, formatBytes, formatDuration, headerValue, looksBinary, OmittedBody, parseMessage, parseOmitted, statusClass } from '../lib/http';
import { diffLines, DiffRow } from '../lib/diff';
import { Attempt } from '../lib/replaySessions';

/** What a sanitized response snapshot offers for comparison. */
interface BodyView {
  text: string | null;
  omitted: OmittedBody | null;
  binary: boolean;
  json: unknown;
}

function bodyOf(r: ReplayResponse): BodyView {
  const msg = parseMessage(r.message);
  const omitted = parseOmitted(msg.body);
  if (omitted) return { text: null, omitted, binary: false, json: undefined };
  const chunked = (headerValue(r.headers, 'transfer-encoding') ?? '').toLowerCase().includes('chunked');
  const bytes = chunked ? dechunk(msg.body) ?? msg.body : msg.body;
  if (looksBinary(bytes)) return { text: null, omitted: null, binary: true, json: undefined };
  const text = bytesToText(bytes);
  let json: unknown;
  try {
    json = text.trim() ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { text, omitted: null, binary: false, json };
}

const CONTEXT = 3;

/** Side-by-side rows; long unchanged runs fold into one line unless expanded. */
const DiffTable: React.FC<{ rows: DiffRow[]; label: string; showAll: boolean }> = ({ rows, label, showAll }) => {
  const near = new Set<number>();
  rows.forEach((r, i) => {
    if (r.kind !== 'same') for (let k = i - CONTEXT; k <= i + CONTEXT; k++) near.add(k);
  });
  const out: React.ReactNode[] = [];
  for (let i = 0; i < rows.length; i++) {
    if (!showAll && rows[i].kind === 'same' && !near.has(i)) {
      let j = i;
      while (j < rows.length && rows[j].kind === 'same' && !near.has(j)) j++;
      out.push(
        <tr key={`f${i}`} className="diff-fold">
          <td colSpan={4}>{j - i} unchanged {j - i === 1 ? 'line' : 'lines'}</td>
        </tr>,
      );
      i = j - 1;
      continue;
    }
    const r = rows[i];
    out.push(
      <tr key={i} className={`diff-${r.kind}`}>
        <td className="ln">{r.left?.no ?? ''}</td>
        <td className="code side-a">{r.left?.text ?? ''}</td>
        <td className="ln">{r.right?.no ?? ''}</td>
        <td className="code side-b">{r.right?.text ?? ''}</td>
      </tr>,
    );
  }
  return (
    <table className="diff-table" aria-label={label}>
      <tbody>{out}</tbody>
    </table>
  );
};

function bodyLabel(b: BodyView): string {
  if (b.omitted) return `not stored (${b.omitted.reason})`;
  if (b.binary) return 'binary, not shown';
  return b.text ? `stored, ${formatBytes(new TextEncoder().encode(b.text).length)}` : 'empty';
}

export const ReplayCompare: React.FC<{ a: Attempt; b: Attempt }> = ({ a, b }) => {
  const [formatJson, setFormatJson] = useState(true);
  const [showAll, setShowAll] = useState(false);
  const ra = a.response!;
  const rb = b.response!;
  const ba = useMemo(() => bodyOf(ra), [ra]);
  const bb = useMemo(() => bodyOf(rb), [rb]);
  const bothJson = ba.json !== undefined && bb.json !== undefined;

  const headerDiff = useMemo(
    () => diffLines(ra.headers.map(([k, v]) => `${k}: ${v}`), rb.headers.map(([k, v]) => `${k}: ${v}`)),
    [ra, rb],
  );
  const bodyDiff = useMemo(() => {
    if (ba.text === null || bb.text === null) return null;
    const lines = (v: BodyView) => (bothJson && formatJson ? JSON.stringify(v.json, null, 2) : (v.text as string)).split(/\r?\n/);
    return diffLines(lines(ba), lines(bb));
  }, [ba, bb, bothJson, formatJson]);

  const facts: [string, string, string][] = [
    ['Status', `${ra.status} ${ra.reason}`, `${rb.status} ${rb.reason}`],
    ['Duration', formatDuration(ra.duration_ms), formatDuration(rb.duration_ms)],
    ['Received', `${formatBytes(ra.total_bytes)} (${ra.total_bytes.toLocaleString()} B)`, `${formatBytes(rb.total_bytes)} (${rb.total_bytes.toLocaleString()} B)`],
    ['Body', bodyLabel(ba), bodyLabel(bb)],
    ['Body SHA-256', ba.omitted?.sha256 ?? '-', bb.omitted?.sha256 ?? '-'],
  ];
  const summary = (d: { added: number; removed: number; changed: number }) =>
    d.added + d.removed + d.changed === 0 ? 'identical' : `${d.changed} changed, ${d.removed} removed, ${d.added} added`;

  return (
    <div className="compare" aria-label="Response comparison">
      <div className="compare-head">
        <span className="compare-side">
          <span className="ab a">A</span> #{a.seq} · {new Date(a.at).toLocaleTimeString()}
        </span>
        <span className="compare-side">
          <span className="ab b">B</span> #{b.seq} · {new Date(b.at).toLocaleTimeString()}
        </span>
        <span className="chrome-spacer" />
        {bothJson && (
          <span className="segmented" role="group" aria-label="JSON display">
            <button aria-pressed={formatJson} onClick={() => setFormatJson(true)}>
              Formatted JSON
            </button>
            <button aria-pressed={!formatJson} onClick={() => setFormatJson(false)}>
              As received
            </button>
          </span>
        )}
        <button className="link-btn" onClick={() => setShowAll((s) => !s)}>
          {showAll ? 'Fold unchanged lines' : 'Show unchanged lines'}
        </button>
      </div>
      <div className="compare-scroll">
        <p className="compare-note">
          Sanitized snapshots only: redacted values stay [REDACTED] on both sides and bodies DropSuite did not store are never shown. Equal hashes mean equal bodies, nothing more.
        </p>
        <table className="kv compare-facts">
          <thead>
            <tr>
              <th />
              <th>A · #{a.seq}</th>
              <th>B · #{b.seq}</th>
            </tr>
          </thead>
          <tbody>
            {facts.map(([k, va, vb]) => (
              <tr key={k} className={va !== vb ? 'differs' : undefined}>
                <td className="k">{k}</td>
                <td className={k === 'Status' ? `mono ${statusClass(ra.status)}` : 'mono'}>{va}</td>
                <td className={k === 'Status' ? `mono ${statusClass(rb.status)}` : 'mono'}>{vb}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <h3 className="compare-title">
          Headers <span>{summary(headerDiff)}</span>
        </h3>
        <DiffTable rows={headerDiff.rows} label="Header differences" showAll={showAll} />

        <h3 className="compare-title">
          Body <span>{bodyDiff ? summary(bodyDiff) + (bodyDiff.approximate ? ' (approximate: compared line by line)' : '') : 'not compared'}</span>
        </h3>
        {bodyDiff ? (
          bodyDiff.rows.length ? (
            <DiffTable rows={bodyDiff.rows} label="Body differences" showAll={showAll} />
          ) : (
            <div className="body-empty">Both responses have no body.</div>
          )
        ) : (
          <div className="msg-state">
            <strong>Full body comparison is unavailable.</strong>{' '}
            {ba.omitted || bb.omitted
              ? 'At least one body was not stored (over the 16 KB capture limit, compressed, binary or incomplete), so only the metadata above can be compared.'
              : 'At least one body is binary and is not shown.'}
          </div>
        )}
      </div>
    </div>
  );
};
