import React, { useMemo, useState } from 'react';
import { ArrowLeftRight, Trash2 } from 'lucide-react';
import { diffLines } from '../lib/diff';

interface ComparerWorkspaceProps {
  active: boolean;
  onToast: (msg: string) => void;
}

const SAMPLE_A = 'GET /api/user?id=1 HTTP/1.1\nHost: lumens.my.id\nAccept: application/json';
const SAMPLE_B = 'GET /api/user?id=2 HTTP/1.1\nHost: lumens.my.id\nAccept: application/json\nX-Trace: on';

export const ComparerWorkspace: React.FC<ComparerWorkspaceProps> = ({ active, onToast }) => {
  const [a, setA] = useState(SAMPLE_A);
  const [b, setB] = useState(SAMPLE_B);

  const diff = useMemo(() => diffLines(a.split('\n'), b.split('\n')), [a, b]);
  const changes = diff.added + diff.removed + diff.changed;
  const summary = changes === 0 ? 'identical' : `${diff.changed} changed · ${diff.removed} removed · ${diff.added} added`;

  const swap = () => {
    setA(b);
    setB(a);
  };
  const clearAll = () => {
    setA('');
    setB('');
    onToast('Cleared both sides.');
  };

  return (
    <div className="workspace comparer" style={{ display: active ? 'flex' : 'none', flex: 1, flexDirection: 'column' }}>
      <div className="cmp-grid">
        <section className="fz-card" aria-label="Side A">
          <div className="fz-card-head">
            <span className="fz-title">
              <span className="ab a">A</span> First
            </span>
            <span className="fz-count">{a.split('\n').length} lines</span>
            <button className="btn" onClick={swap} title="Swap A and B" style={{ marginLeft: 'auto' }}>
              <ArrowLeftRight size={12} /> Swap
            </button>
          </div>
          <textarea className="fz-area cmp-area" value={a} onChange={(e) => setA(e.target.value)} spellCheck={false} aria-label="Text A" />
        </section>
        <section className="fz-card" aria-label="Side B">
          <div className="fz-card-head">
            <span className="fz-title">
              <span className="ab b">B</span> Second
            </span>
            <span className="fz-count">{b.split('\n').length} lines</span>
            <button className="btn" onClick={clearAll} title="Clear both" style={{ marginLeft: 'auto' }}>
              <Trash2 size={12} /> Clear
            </button>
          </div>
          <textarea className="fz-area cmp-area" value={b} onChange={(e) => setB(e.target.value)} spellCheck={false} aria-label="Text B" />
        </section>
      </div>

      <section className="fz-results cmp-results" aria-label="Differences">
        <div className="fz-results-head">
          <span className="fz-title">Differences</span>
          <span className="fz-count">{summary}{diff.approximate ? ' · approximate' : ''}</span>
        </div>
        <div className="fz-table-wrap">
          <table className="diff-table" aria-label="Line differences">
            <tbody>
              {diff.rows.map((r, i) => (
                <tr key={i} className={`diff-${r.kind}`}>
                  <td className="ln">{r.left?.no ?? ''}</td>
                  <td className="code side-a">{r.left?.text ?? ''}</td>
                  <td className="ln">{r.right?.no ?? ''}</td>
                  <td className="code side-b">{r.right?.text ?? ''}</td>
                </tr>
              ))}
              {diff.rows.length === 0 && (
                <tr>
                  <td colSpan={4} className="fz-empty">Both sides are empty.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
