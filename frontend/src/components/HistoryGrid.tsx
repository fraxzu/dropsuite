import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { ArrowDown, ArrowUp } from 'lucide-react';
import { TransactionSummary } from '../types';
import { displayPath, formatBytes, formatClock, formatDuration, shortType, splitPathQuery, statusClass } from '../lib/http';

export type SortKey = 'id' | 'method' | 'host' | 'path' | 'status' | 'type' | 'length' | 'duration' | 'time';
export interface SortState {
  key: SortKey;
  dir: 'asc' | 'desc';
}

const ROW = 24;
const OVERSCAN = 12;

const COLUMNS: { key: SortKey; label: string; right?: boolean; className?: string; title?: string }[] = [
  { key: 'id', label: '#', right: true },
  { key: 'method', label: 'Method' },
  { key: 'host', label: 'Host' },
  { key: 'path', label: 'Path' },
  { key: 'status', label: 'Status' },
  { key: 'type', label: 'Type', className: 'col-type' },
  { key: 'length', label: 'Length', right: true, title: 'Size of the captured response, head and body' },
  { key: 'duration', label: 'Duration', right: true, title: 'Time from forwarding the request to receiving the response' },
  { key: 'time', label: 'Time', className: 'col-time', title: 'Local time the request was captured' },
];

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function sortRows(rows: TransactionSummary[], sort: SortState): TransactionSummary[] {
  const dir = sort.dir === 'asc' ? 1 : -1;
  const val = (t: TransactionSummary): string | number => {
    switch (sort.key) {
      case 'id':
        return t.id;
      case 'method':
        return t.method;
      case 'host':
        return t.host;
      case 'path':
        return displayPath(t);
      case 'status':
        return t.status_code;
      case 'type':
        return shortType(t.content_type);
      case 'length':
        return t.content_length;
      case 'duration':
        return t.duration_ms;
      case 'time':
        return t.timestamp;
    }
  };
  return [...rows].sort((a, b) => {
    const va = val(a);
    const vb = val(b);
    if (va < vb) return -dir;
    if (va > vb) return dir;
    return b.id - a.id;
  });
}

interface HistoryGridProps {
  rows: TransactionSummary[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  onMove: (to: number | 'start' | 'end') => void;
  onClearSelection: () => void;
  sort: SortState;
  onSort: (s: SortState) => void;
  arrived: Set<number>;
  label: string;
  /** Shown instead of rows when there are none. */
  empty: React.ReactNode;
  loading: boolean;
  gridRef?: React.RefObject<HTMLDivElement>;
}

export const HistoryGrid: React.FC<HistoryGridProps> = ({
  rows,
  selectedId,
  onSelect,
  onMove,
  onClearSelection,
  sort,
  onSort,
  arrived,
  label,
  empty,
  loading,
  gridRef,
}) => {
  const localRef = useRef<HTMLDivElement>(null);
  const bodyRef = gridRef ?? localRef;
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(400);

  useLayoutEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    ro.observe(el);
    setHeight(el.clientHeight);
    return () => ro.disconnect();
  }, [bodyRef, rows.length === 0]);

  // Keep the selected row in view when selection moves by keyboard or from the timeline.
  useEffect(() => {
    const el = bodyRef.current;
    if (!el || selectedId === null) return;
    const idx = rows.findIndex((r) => r.id === selectedId);
    if (idx === -1) return;
    const top = idx * ROW;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + ROW > el.scrollTop + el.clientHeight) el.scrollTop = top + ROW - el.clientHeight;
  }, [selectedId, rows, bodyRef]);

  const first = Math.max(0, Math.floor(scrollTop / ROW) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + height) / ROW) + OVERSCAN);
  const pageRows = Math.max(1, Math.floor(height / ROW) - 1);
  const selectedIndex = selectedId === null ? -1 : rows.findIndex((r) => r.id === selectedId);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const cur = selectedIndex;
    switch (e.key) {
      case 'ArrowDown':
      case 'j':
        onMove(cur === -1 ? 0 : cur + 1);
        break;
      case 'ArrowUp':
      case 'k':
        onMove(cur === -1 ? 0 : cur - 1);
        break;
      case 'PageDown':
        onMove(Math.max(0, cur) + pageRows);
        break;
      case 'PageUp':
        onMove(Math.max(0, cur) - pageRows);
        break;
      case 'Home':
        onMove('start');
        break;
      case 'End':
        onMove('end');
        break;
      case 'Escape':
        if (selectedId === null) return;
        onClearSelection();
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  };

  const header = (
    <div className="grid-head grid-cols" role="row">
      {COLUMNS.map((c) => {
        const active = sort.key === c.key;
        return (
          <button
            key={c.key}
            role="columnheader"
            aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
            className={`th${c.right ? ' right' : ''}${c.className ? ` ${c.className}` : ''}`}
            title={c.title}
            onClick={() => onSort({ key: c.key, dir: active && sort.dir === 'desc' ? 'asc' : active ? 'desc' : c.key === 'id' || c.key === 'time' ? 'desc' : 'asc' })}
          >
            {c.label}
            {active && (sort.dir === 'asc' ? <ArrowUp size={11} /> : <ArrowDown size={11} />)}
          </button>
        );
      })}
    </div>
  );

  if (loading) {
    return (
      <div className="grid-wrap" aria-busy="true">
        {header}
        <div className="grid-body">
          {Array.from({ length: 10 }, (_, i) => (
            <div key={i} className="skeleton-row" style={{ opacity: 1 - i * 0.08 }}>
              <span className="skeleton-bar" style={{ width: 24 }} />
              <span className="skeleton-bar" style={{ width: 36 }} />
              <span className="skeleton-bar" style={{ width: 110 }} />
              <span className="skeleton-bar" style={{ width: 220 + ((i * 37) % 120) }} />
              <span className="skeleton-bar" style={{ width: 28 }} />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="grid-wrap">
      {header}
      {rows.length === 0 ? (
        <div className="grid-body">{empty}</div>
      ) : (
        <div
          ref={bodyRef}
          className="grid-body"
          role="grid"
          aria-label={label}
          aria-rowcount={rows.length}
          aria-activedescendant={selectedId !== null && selectedIndex !== -1 ? `row-${selectedId}` : undefined}
          tabIndex={0}
          onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
          onKeyDown={onKeyDown}
        >
          <div style={{ height: rows.length * ROW, position: 'relative' }}>
            {rows.slice(first, last).map((t, i) => {
              const idx = first + i;
              const { pathname, query } = splitPathQuery(displayPath(t));
              const m = t.method.toUpperCase();
              return (
                <div
                  key={t.id}
                  id={`row-${t.id}`}
                  role="row"
                  aria-rowindex={idx + 1}
                  aria-selected={t.id === selectedId}
                  className={`grid-row grid-cols${arrived.has(t.id) ? ' arrived' : ''}`}
                  style={{ transform: `translateY(${idx * ROW}px)` }}
                  onMouseDown={() => onSelect(t.id)}
                >
                  <span role="gridcell" className="td id right">{t.id}</span>
                  <span role="gridcell" className={`td method${WRITE_METHODS.has(m) ? ' write' : ''}`}>
                    {m}
                  </span>
                  <span role="gridcell" className="td host" title={t.host}>
                    {t.host}
                  </span>
                  <span role="gridcell" className="td path" title={pathname + query}>
                    {pathname}
                    {query && <span className="q">{query}</span>}
                  </span>
                  <span role="gridcell" className={`td status ${statusClass(t.status_code)}`}>
                    {t.status_code || '-'}
                  </span>
                  <span role="gridcell" className="td meta col-type" title={t.content_type}>
                    {shortType(t.content_type) || '-'}
                  </span>
                  <span role="gridcell" className="td meta right">{formatBytes(t.content_length)}</span>
                  <span role="gridcell" className="td meta right">{formatDuration(t.duration_ms)}</span>
                  <span role="gridcell" className="td faint col-time">{formatClock(t.timestamp)}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
