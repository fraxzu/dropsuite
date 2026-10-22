import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Copy, Download, Globe, Search, Trash2, X } from 'lucide-react';
import { ProxyStatus, TransactionRecord, TransactionSummary } from '../types';
import { useHistory, useTransaction } from '../lib/api';
import { DESKTOP, DEV_API_BASE, engine } from '../lib/transport';
import { copyText, formatClock, statusClass } from '../lib/http';
import { useStoredState } from '../lib/useStoredState';
import { CaptureTimeline, TimeWindow } from '../components/CaptureTimeline';
import { HistoryGrid, SortState, sortRows } from '../components/HistoryGrid';
import { Inspector } from '../components/Inspector';
import { InterceptPanel } from '../components/InterceptPanel';
import { Splitter } from '../components/Splitter';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const STATUS_CLASSES = [
  { id: 's2', label: '2xx', color: 'var(--s2)' },
  { id: 's3', label: '3xx', color: 'var(--s3)' },
  { id: 's4', label: '4xx', color: 'var(--s4)' },
  { id: 's5', label: '5xx', color: 'var(--s5)' },
];

const MIN_GRID = 120;
/** Requests closer together than this belong to one burst (one click in the target app). */
const BURST_MS = 3000;
const MIN_INSPECTOR = 180;

interface ProxyWorkspaceProps {
  active: boolean;
  status: ProxyStatus | null;
  connected: boolean | null;
  engineError: string | null;
  onLoaded: (n: number) => void;
  onToast: (msg: string) => void;
  onSendToReplay: (record: TransactionRecord) => void;
}

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function isEditable(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  return el.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName);
}

export const ProxyWorkspace: React.FC<ProxyWorkspaceProps> = ({ active, status, connected, engineError, onLoaded, onToast, onSendToReplay }) => {
  const [subtab, setSubtab] = useStoredState<'intercept' | 'history'>('proxy.subtab', 'intercept');
  const [heldCount, setHeldCount] = useState(0);
  const [search, setSearch] = useState('');
  const [method, setMethod] = useState('');
  const [classes, setClasses] = useState<Set<string>>(new Set());
  const [win, setWin] = useState<TimeWindow | null>(null);
  const [sort, setSort] = useStoredState<SortState>('proxy.sort', { key: 'id', dir: 'desc' });
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [inspectorRatio, setInspectorRatio] = useStoredState<number>('proxy.inspector', 0.48);
  const [browserUrl, setBrowserUrl] = useState('https://lumens.my.id/');
  const q = useDebounced(search.trim(), 180);

  const { items, fresh, refresh } = useHistory({ q, method });
  // The timeline always spans the whole capture so its rhythm stays put while filtering.
  const searching = !!(q || method);
  const full = useHistory({ q: '', method: '' }, searching);
  const detail = useTransaction(selectedId);

  const searchRef = useRef<HTMLInputElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const splitRef = useRef<HTMLDivElement>(null);
  const [splitH, setSplitH] = useState(600);

  useLayoutEffect(() => {
    const el = splitRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setSplitH(el.clientHeight));
    ro.observe(el);
    setSplitH(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  // Briefly mark rows that arrived since the previous poll.
  const maxSeen = useRef<number | null>(null);
  const [arrived, setArrived] = useState<Set<number>>(new Set());
  useEffect(() => {
    if (!items || !fresh) return;
    const max = items.reduce((m, t) => Math.max(m, t.id), 0);
    if (maxSeen.current !== null && max > maxSeen.current) {
      const prev = maxSeen.current;
      const added = new Set(items.filter((t) => t.id > prev).map((t) => t.id));
      setArrived(added);
      const t = setTimeout(() => setArrived(new Set()), 1700);
      maxSeen.current = max;
      return () => clearTimeout(t);
    }
    maxSeen.current = Math.max(maxSeen.current ?? 0, max);
  }, [items, fresh]);

  useEffect(() => {
    if (items && !q && !method) onLoaded(items.length);
  }, [items, q, method, onLoaded]);

  const all = items ?? [];
  const byStatus = useMemo(() => (classes.size ? all.filter((t) => classes.has(statusClass(t.status_code))) : all), [all, classes]);
  const visibleIds = useMemo(() => new Set(byStatus.map((t) => t.id)), [byStatus]);
  const rows = useMemo(() => {
    const scoped = win ? byStatus.filter((t) => t.timestamp >= win.from && t.timestamp <= win.to) : byStatus;
    return sortRows(scoped, sort);
  }, [byStatus, win, sort]);

  // Keep the inspected request on screen even when a filter hides its row.
  const lastSummary = useRef<TransactionSummary | null>(null);
  const found = useMemo(() => all.find((t) => t.id === selectedId) ?? null, [all, selectedId]);
  if (found) lastSummary.current = found;
  const summary: TransactionSummary | null = selectedId === null ? null : found ?? (lastSummary.current?.id === selectedId ? lastSummary.current : null);
  const filtersActive = !!(search || method || classes.size || win);

  const move = (to: number | 'start' | 'end') => {
    if (!rows.length) return;
    const i = to === 'start' ? 0 : to === 'end' ? rows.length - 1 : Math.min(rows.length - 1, Math.max(0, to));
    setSelectedId(rows[i].id);
  };

  /** Scope the grid to the burst around the selected request: neighbours chained within BURST_MS. */
  const scopeToBurst = () => {
    if (win) {
      setWin(null);
      return;
    }
    const pool = (searching ? full.items : null) ?? all;
    const sel = pool.find((t) => t.id === selectedId);
    if (!sel) {
      onToast('Select a request first, then press b to scope to its burst');
      return;
    }
    const sorted = [...pool].sort((a, b) => a.timestamp - b.timestamp);
    let i = sorted.indexOf(sel);
    let j = i;
    while (i > 0 && sorted[i].timestamp - sorted[i - 1].timestamp <= BURST_MS) i--;
    while (j < sorted.length - 1 && sorted[j + 1].timestamp - sorted[j].timestamp <= BURST_MS) j++;
    setWin({ from: sorted[i].timestamp, to: sorted[j].timestamp });
    onToast(`Scoped to burst: ${j - i + 1} requests. Press b or Esc to clear`);
  };

  const clearFilters = () => {
    setSearch('');
    setMethod('');
    setClasses(new Set());
    setWin(null);
  };

  const exportHarFile = async () => {
    const idsToExport = selectedId !== null ? [selectedId] : rows.map((r) => r.id);
    if (idsToExport.length === 0) {
      onToast('No requests available to export');
      return;
    }
    try {
      const harJson = await engine.exportHar(idsToExport);
      const blob = new Blob([harJson], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dropsuite-history-${Date.now()}.har`;
      a.click();
      URL.revokeObjectURL(url);
      onToast(`Exported ${idsToExport.length} request(s) to HAR`);
    } catch (err) {
      onToast(`HAR export failed: ${err}`);
    }
  };

  const clearHistoryAll = async () => {
    const n = rows.length;
    if (n === 0) {
      onToast('History is already empty');
      return;
    }
    if (!window.confirm(`Delete all ${n} captured request(s)? This also clears the site map and passive scanner. Repeater tabs are kept. This cannot be undone.`)) {
      return;
    }
    try {
      const removed = await engine.clearHistory();
      setSelectedId(null);
      maxSeen.current = null;
      await refresh();
      onToast(`Cleared ${removed} request(s) from history`);
    } catch (err) {
      onToast(`Clear failed: ${err}`);
    }
  };

  // Workspace keys that work from anywhere outside a text field.
  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === 'Escape' && document.activeElement === searchRef.current) {
        if (search) setSearch('');
        else gridRef.current?.focus();
        e.preventDefault();
        return;
      }
      if (isEditable(e.target)) return;
      if (e.key === '/') {
        searchRef.current?.focus();
        searchRef.current?.select();
        e.preventDefault();
      } else if ((e.key === 'j' || e.key === 'k') && !gridRef.current?.contains(document.activeElement)) {
        const cur = rows.findIndex((r) => r.id === selectedId);
        move(cur === -1 ? 0 : cur + (e.key === 'j' ? 1 : -1));
        gridRef.current?.focus({ preventScroll: true });
        e.preventDefault();
      } else if (e.key === 'r' && detail.state.kind === 'ready' && detail.state.record.id === selectedId) {
        onSendToReplay(detail.state.record);
        e.preventDefault();
      } else if (e.key === 'b') {
        scopeToBurst();
        e.preventDefault();
      } else if (e.key === 'Escape') {
        if (selectedId !== null) setSelectedId(null);
        else if (win) setWin(null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const toggleClass = (id: string) =>
    setClasses((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const inspectorPx = Math.min(splitH - MIN_GRID, Math.max(MIN_INSPECTOR, splitH * inspectorRatio));
  const captured = Math.max(status?.total_captured ?? 0, all.length);
  const listenAddr = status ? `${status.bind_address}:${status.port}` : '127.0.0.1:8080';

  let empty: React.ReactNode;
  if (connected === false && all.length === 0) {
    empty = DESKTOP ? (
      <div className="state error" role="alert">
        <h2>
          <AlertTriangle size={16} /> DropSuite's capture engine isn't available
        </h2>
        <p>{engineError ?? 'The engine did not respond.'}</p>
        <p className="note">Close DropSuite and open it again. If this keeps happening, another copy may be holding the history database.</p>
      </div>
    ) : (
      <div className="state error" role="alert">
        <h2>
          <AlertTriangle size={16} /> Can't reach the DropSuite daemon
        </h2>
        <p>
          The interface asks <span className="mono">{DEV_API_BASE.replace(/^https?:\/\//, '')}</span> for traffic every 1.5 seconds and got no answer. Start <span className="mono">dropsuite-desktop</span> and this view reconnects on its own.
        </p>
      </div>
    );
  } else if (filtersActive) {
    empty = (
      <div className="state">
        <h2>No requests match these filters</h2>
        <p>
          {captured > 0
            ? `None of the ${captured.toLocaleString()} captured requests match the current search, method, status or time window.`
            : 'Nothing has been captured yet, so there is nothing to match.'}
        </p>
        <div className="actions">
          <button className="btn" onClick={clearFilters}>
            Clear filters
          </button>
        </div>
      </div>
    );
  } else {
    empty = (
      <div className="state">
        <h2>No traffic captured yet</h2>
        <p>Point your browser or HTTP client at the proxy listener. Requests appear here the moment they pass through.</p>
        <span className="endpoint">
          {listenAddr}
          <button
            className="icon-btn"
            aria-label="Copy proxy address"
            onClick={async () => {
              if (await copyText(listenAddr)) onToast('Proxy address copied');
            }}
          >
            <Copy size={13} />
          </button>
        </span>
        <p className="note">HTTPS interception is active for allowlisted hosts via the local DropSuite CA. Other HTTPS traffic is tunneled directly.</p>
        {status && !status.is_running && <p className="note">The listener is stopped. Start it from the top bar.</p>}
      </div>
    );
  }

  return (
    <div className="workspace" style={{ display: active ? 'flex' : 'none', flex: 1, flexDirection: 'column' }}>
      {/* Subtab Bar: Intercept | HTTP history */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 4,
          padding: '4px 12px 0 12px',
          background: 'var(--chrome)',
          borderBottom: '1px solid var(--line)',
          flexShrink: 0,
        }}
      >
        <button
          type="button"
          onClick={() => setSubtab('intercept')}
          style={{
            padding: '5px 14px',
            fontSize: 12,
            fontWeight: subtab === 'intercept' ? 600 : 500,
            background: subtab === 'intercept' ? 'var(--panel)' : 'transparent',
            color: subtab === 'intercept' ? 'var(--text)' : 'var(--text-3)',
            border: '1px solid',
            borderColor: subtab === 'intercept' ? 'var(--line)' : 'transparent',
            borderBottomColor: subtab === 'intercept' ? 'var(--panel)' : 'transparent',
            borderTopLeftRadius: 4,
            borderTopRightRadius: 4,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            marginBottom: -1,
          }}
        >
          Intercept
          {heldCount > 0 && (
            <span
              style={{
                background: 'var(--accent)',
                color: '#fff',
                fontSize: 10,
                fontWeight: 700,
                padding: '1px 5px',
                borderRadius: 10,
              }}
            >
              {heldCount}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setSubtab('history')}
          style={{
            padding: '5px 14px',
            fontSize: 12,
            fontWeight: subtab === 'history' ? 600 : 500,
            background: subtab === 'history' ? 'var(--panel)' : 'transparent',
            color: subtab === 'history' ? 'var(--text)' : 'var(--text-3)',
            border: '1px solid',
            borderColor: subtab === 'history' ? 'var(--line)' : 'transparent',
            borderBottomColor: subtab === 'history' ? 'var(--panel)' : 'transparent',
            borderTopLeftRadius: 4,
            borderTopRightRadius: 4,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            marginBottom: -1,
          }}
        >
          HTTP history
          {items && items.length > 0 && (
            <span style={{ fontSize: 11, color: 'var(--text-3)' }}>
              ({items.length.toLocaleString()})
            </span>
          )}
        </button>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, paddingBottom: 4 }}>
          <select
            className="text-input"
            value={browserUrl}
            onChange={(e) => setBrowserUrl(e.target.value)}
            style={{ fontSize: 11, padding: '3px 6px', maxWidth: 160 }}
            title="Select target or badssl test URL"
          >
            <option value="https://lumens.my.id/">lumens.my.id (OK)</option>
            <option value="https://expired.badssl.com/">expired.badssl.com</option>
            <option value="https://self-signed.badssl.com/">self-signed.badssl.com</option>
            <option value="https://wrong.host.badssl.com/">wrong.host.badssl.com</option>
          </select>
          <input
            className="text-input mono"
            placeholder="Target URL..."
            value={browserUrl}
            onChange={(e) => setBrowserUrl(e.target.value)}
            style={{ width: 180, fontSize: 11, padding: '3px 8px' }}
          />
          <button
            type="button"
            className="btn"
            onClick={async () => {
              try {
                await engine.openBrowser(browserUrl);
                onToast(`Embedded browser launched (${browserUrl})`);
              } catch (e) {
                onToast(`Could not open browser: ${e}`);
              }
            }}
            title="Open Pre-configured Embedded Browser (Isolated, Proxy & CA Auto-configured)"
            style={{
              padding: '4px 10px',
              fontSize: 11,
              fontWeight: 500,
              background: 'var(--raised)',
              border: '1px solid var(--line)',
              borderRadius: 4,
              color: 'var(--text)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              cursor: 'pointer',
              whiteSpace: 'nowrap',
            }}
          >
            <Globe size={13} style={{ color: 'var(--accent)' }} />
            Open Browser
          </button>
        </div>
      </div>

      {subtab === 'intercept' ? (
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
          <InterceptPanel
            active={active && subtab === 'intercept'}
            onToast={onToast}
            onQueueCountChange={setHeldCount}
          />
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div className="toolbar" role="toolbar" aria-label="History filters">
            <div className="search">
              <Search size={13} />
              <input
                ref={searchRef}
                type="search"
                aria-label="Filter history by URL, host or path"
                placeholder="Filter by URL, host or path"
                value={search}
                spellCheck={false}
                onChange={(e) => setSearch(e.target.value)}
              />
              {search ? (
                <button className="icon-btn clear" aria-label="Clear search" onClick={() => setSearch('')}>
                  <X size={12} />
                </button>
              ) : (
                <kbd aria-hidden="true">/</kbd>
              )}
            </div>
            <select className="select" aria-label="Method" value={method} onChange={(e) => setMethod(e.target.value)}>
              <option value="">All methods</option>
              {METHODS.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <div className="segmented" role="group" aria-label="Status class">
              {STATUS_CLASSES.map((c) => (
                <button
                  key={c.id}
                  aria-pressed={classes.has(c.id)}
                  style={{ '--seg-color': c.color } as React.CSSProperties}
                  onClick={() => toggleClass(c.id)}
                  title={`Show only ${c.label} responses`}
                >
                  {c.label}
                </button>
              ))}
            </div>
            {win && (
              <span className="chip" aria-label="Time window filter">
                {formatClock(win.from)} – {formatClock(win.to)}
                <button className="icon-btn" aria-label="Clear time window" onClick={() => setWin(null)}>
                  <X size={11} />
                </button>
              </span>
            )}
            <button
              className="btn"
              onClick={exportHarFile}
              title={selectedId !== null ? `Export selected request (#${selectedId}) as HAR 1.2` : `Export all ${rows.length} filtered requests as HAR 1.2`}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '0 8px', height: 24, fontSize: 11 }}
            >
              <Download size={12} /> HAR
            </button>
            <button
              className="btn"
              onClick={clearHistoryAll}
              disabled={rows.length === 0}
              title="Delete all captured history (also clears the site map and passive scanner; Repeater tabs are kept)"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '0 8px', height: 24, fontSize: 11 }}
            >
              <Trash2 size={12} /> Clear
            </button>
            <div className="toolbar-meta">
              {filtersActive && (
                <button className="link-btn" onClick={clearFilters}>
                  Clear filters
                </button>
              )}
              <span aria-live="polite">
                <strong className="num">{rows.length.toLocaleString()}</strong>
                {filtersActive ? ` of ${captured.toLocaleString()} match` : rows.length === 1 ? ' request' : ' requests'}
              </span>
            </div>
          </div>

          <CaptureTimeline items={searching ? full.items ?? all : all} visible={visibleIds} selectedId={selectedId} window={win} onWindow={setWin} onSelect={setSelectedId} />

          <div className="split-v" ref={splitRef}>
            <div className="pane" style={{ flex: 1, minHeight: MIN_GRID }}>
              <HistoryGrid
                rows={rows}
                selectedId={selectedId}
                onSelect={setSelectedId}
                onMove={move}
                onClearSelection={() => setSelectedId(null)}
                sort={sort}
                onSort={setSort}
                arrived={arrived}
                label="HTTP history"
                empty={empty}
                loading={items === null && connected !== false}
                gridRef={gridRef}
              />
            </div>
            <Splitter
              orientation="horizontal"
              label="Resize history and inspector"
              value={inspectorPx}
              min={MIN_INSPECTOR}
              max={splitH - MIN_GRID}
              invert
              onChange={(px) => setInspectorRatio(px / splitH)}
              onReset={() => setInspectorRatio(0.48)}
            />
            <div className="pane" style={{ height: inspectorPx, flexShrink: 0 }}>
              <Inspector summary={summary} detail={detail.state} onRetry={detail.retry} onCopied={onToast} onSendToReplay={onSendToReplay} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

