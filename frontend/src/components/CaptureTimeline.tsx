import React, { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { TransactionSummary } from '../types';
import { displayPath, formatClock, statusClass } from '../lib/http';

export interface TimeWindow {
  from: number;
  to: number;
}

interface CaptureTimelineProps {
  items: TransactionSummary[];
  /** IDs that pass the search, method and status filters; others render dimmed. */
  visible: Set<number>;
  selectedId: number | null;
  window: TimeWindow | null;
  onWindow: (w: TimeWindow | null) => void;
  onSelect: (id: number) => void;
}

/** Idle stretches longer than this collapse into a fixed-width break mark. */
const GAP_MS = 45_000;
const PAD_L = 64;
const PAD_R = 64;
const BREAK_PX = 14;

const STATUS_FILL: Record<string, string> = {
  s1: 'var(--s1)',
  s2: 'var(--s2)',
  s3: 'var(--s3)',
  s4: 'var(--s4)',
  s5: 'var(--s5)',
  s0: 'var(--text-3)',
};

interface Layout {
  xs: Map<number, number>;
  gaps: { x: number; ms: number }[];
  sorted: TransactionSummary[];
}

/**
 * Piecewise time scale: active stretches keep their real proportions,
 * idle stretches beyond GAP_MS shrink to a break, so a session that spans
 * hours still shows the bursts that matter.
 */
function layoutTicks(items: TransactionSummary[], width: number): Layout {
  const sorted = [...items].sort((a, b) => a.timestamp - b.timestamp || a.id - b.id);
  const xs = new Map<number, number>();
  const gaps: { x: number; ms: number }[] = [];
  if (sorted.length === 0) return { xs, gaps, sorted };

  let activeMs = 0;
  let breaks = 0;
  for (let i = 1; i < sorted.length; i++) {
    const d = sorted[i].timestamp - sorted[i - 1].timestamp;
    if (d > GAP_MS) breaks++;
    else activeMs += d;
  }
  const usable = Math.max(40, width - PAD_L - PAD_R - breaks * BREAK_PX);
  const pxPerMs = activeMs > 0 ? usable / activeMs : 0;

  let x = sorted.length === 1 || activeMs === 0 ? PAD_L + usable / 2 : PAD_L;
  // With no measurable active time, spread ticks evenly rather than stacking them.
  const even = activeMs === 0 && sorted.length > 1 ? (usable + breaks * BREAK_PX) / (sorted.length - 1) : 0;
  if (even) x = PAD_L;
  xs.set(sorted[0].id, x);
  for (let i = 1; i < sorted.length; i++) {
    const d = sorted[i].timestamp - sorted[i - 1].timestamp;
    if (even) {
      x += even;
    } else if (d > GAP_MS) {
      gaps.push({ x: x + BREAK_PX / 2, ms: d });
      x += BREAK_PX;
    } else {
      x += d * pxPerMs;
    }
    xs.set(sorted[i].id, x);
  }
  return { xs, gaps, sorted };
}

function formatGap(ms: number): string {
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m} min idle`;
  const h = Math.floor(m / 60);
  return `${h} h ${m % 60} min idle`;
}

export const CaptureTimeline: React.FC<CaptureTimelineProps> = ({ items, visible, selectedId, window: win, onWindow, onSelect }) => {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);
  const [hover, setHover] = useState<{ t: TransactionSummary; x: number } | null>(null);
  const [drag, setDrag] = useState<{ x0: number; x1: number } | null>(null);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    setWidth(el.clientWidth);
    return () => ro.disconnect();
  }, []);

  const { xs, gaps, sorted } = useMemo(() => layoutTicks(items, width), [items, width]);
  const H = 34;
  const tickTop = 9;
  const tickH = 14;

  const localX = (e: React.PointerEvent) => e.clientX - (ref.current?.getBoundingClientRect().left ?? 0);

  const nearest = (x: number): TransactionSummary | null => {
    let best: TransactionSummary | null = null;
    let bestD = Infinity;
    for (const t of sorted) {
      const d = Math.abs((xs.get(t.id) ?? 0) - x);
      if (d < bestD) {
        bestD = d;
        best = t;
      }
    }
    return bestD <= 12 ? best : null;
  };

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0 || sorted.length === 0) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    const x = localX(e);
    setDrag({ x0: x, x1: x });
  };

  const onPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const x = localX(e);
    if (drag) {
      setDrag({ ...drag, x1: x });
      setHover(null);
      return;
    }
    const t = nearest(x);
    setHover(t ? { t, x: xs.get(t.id) ?? x } : null);
  };

  const onPointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!drag) return;
    const x = localX(e);
    const lo = Math.min(drag.x0, x);
    const hi = Math.max(drag.x0, x);
    setDrag(null);
    if (hi - lo < 4) {
      const t = nearest(x);
      if (t) onSelect(t.id);
      return;
    }
    const inside = sorted.filter((t) => {
      const tx = xs.get(t.id) ?? 0;
      return tx >= lo && tx <= hi;
    });
    if (inside.length) onWindow({ from: inside[0].timestamp, to: inside[inside.length - 1].timestamp });
  };

  // Window rectangle in pixel space.
  let winRect: { x: number; w: number } | null = null;
  if (win) {
    const inWin = sorted.filter((t) => t.timestamp >= win.from && t.timestamp <= win.to);
    if (inWin.length) {
      const a = (xs.get(inWin[0].id) ?? 0) - 4;
      const b = (xs.get(inWin[inWin.length - 1].id) ?? 0) + 4;
      winRect = { x: a, w: Math.max(8, b - a) };
    }
  }
  const dragRect = drag ? { x: Math.min(drag.x0, drag.x1), w: Math.abs(drag.x1 - drag.x0) } : null;
  const selX = selectedId !== null ? xs.get(selectedId) : undefined;
  const first = sorted[0];
  const lastT = sorted[sorted.length - 1];

  return (
    <div
      ref={ref}
      className="timeline"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerLeave={() => setHover(null)}
      onDoubleClick={() => onWindow(null)}
      title={sorted.length ? 'Drag across a burst to scope the history to it. Click a tick to select that request. Double-click to clear.' : undefined}
    >
      {sorted.length === 0 ? (
        <div className="timeline-empty">Capture timeline: requests appear here as they arrive.</div>
      ) : (
        <svg role="img" aria-label={`Capture timeline: ${sorted.length} requests from ${formatClock(first.timestamp)} to ${formatClock(lastT.timestamp)}${gaps.length ? `, ${gaps.length} idle gaps collapsed` : ''}`}>
          <line x1={PAD_L - 8} x2={width - PAD_R + 8} y1={tickTop + tickH + 0.5} y2={tickTop + tickH + 0.5} stroke="var(--line-strong)" />
          <text className="axis-label" x={8} y={tickTop + tickH - 3}>
            {formatClock(first.timestamp)}
          </text>
          <text className="axis-label" x={width - 8} y={tickTop + tickH - 3} textAnchor="end">
            {formatClock(lastT.timestamp)}
          </text>
          {winRect && <rect className="window" x={winRect.x} y={4} width={winRect.w} height={H - 9} rx={2} />}
          {dragRect && <rect className="window" x={dragRect.x} y={4} width={dragRect.w} height={H - 9} rx={2} />}
          {gaps.map((g, i) => (
            <g key={i}>
              <title>{formatGap(g.ms)}</title>
              <rect x={g.x - 5} y={tickTop + tickH - 4} width={10} height={9} fill="var(--ground)" />
              <line className="gap-mark" x1={g.x - 3.5} x2={g.x - 0.5} y1={tickTop + tickH + 4} y2={tickTop + tickH - 4} />
              <line className="gap-mark" x1={g.x + 0.5} x2={g.x + 3.5} y1={tickTop + tickH + 4} y2={tickTop + tickH - 4} />
            </g>
          ))}
          {sorted.map((t) => {
            const x = Math.round(xs.get(t.id) ?? 0);
            const sc = statusClass(t.status_code);
            const tall = sc === 's4' || sc === 's5';
            return (
              <rect
                key={t.id}
                className={`tick${visible.has(t.id) ? '' : ' dim'}`}
                x={x}
                y={tall ? tickTop - 3 : tickTop}
                width={2}
                height={tall ? tickH + 3 : tickH}
                fill={STATUS_FILL[sc]}
              />
            );
          })}
          {selX !== undefined && (
            <path className="sel-mark" d={`M${Math.round(selX) + 1 - 4} 1 h8 l-4 5 z`} />
          )}
          {selX !== undefined && <rect x={Math.round(selX) - 1} y={tickTop - 3} width={4} height={tickH + 3} fill="var(--text)" rx={1} />}
        </svg>
      )}
      {hover && !drag && (
        <div className="timeline-tip" style={{ left: Math.min(Math.max(8, hover.x - 120), width - 428) }}>
          <span className="muted">#{hover.t.id} {formatClock(hover.t.timestamp)}</span> {hover.t.method} {hover.t.host}
          {displayPath(hover.t)} <span className={statusClass(hover.t.status_code)}>{hover.t.status_code}</span>
        </div>
      )}
    </div>
  );
};
