import React, { useEffect, useRef, useState } from 'react';

interface SplitterProps {
  /** horizontal = a row seam between stacked panes; vertical = a column seam between side-by-side panes */
  orientation: 'horizontal' | 'vertical';
  /** Size of the pane the seam controls, in px. */
  value: number;
  min: number;
  max: number;
  onChange: (px: number) => void;
  /** Dragging toward the end (down/right) grows the controlled pane when false; shrinks it when true. */
  invert?: boolean;
  onReset?: () => void;
  label: string;
}

export const Splitter: React.FC<SplitterProps> = ({ orientation, value, min, max, onChange, invert, onReset, label }) => {
  const [dragging, setDragging] = useState(false);
  const origin = useRef<{ pos: number; value: number } | null>(null);
  const horizontal = orientation === 'horizontal';

  // Latest props live in a ref so the window listeners (attached once per drag) never read stale
  // values — avoids the WebView2 bug where re-rendering mid-drag silently stops React's synthetic
  // onPointerMove from firing. We drive the drag from real window pointer events instead.
  const live = useRef({ onChange, min, max, invert, horizontal });
  live.current = { onChange, min, max, invert, horizontal };

  useEffect(() => {
    if (!dragging) return;
    const move = (e: PointerEvent) => {
      const o = origin.current;
      if (!o) return;
      const s = live.current;
      const delta = (s.horizontal ? e.clientY : e.clientX) - o.pos;
      const next = o.value + (s.invert ? -delta : delta);
      s.onChange(Math.round(Math.min(s.max, Math.max(s.min, next))));
    };
    const end = () => {
      origin.current = null;
      setDragging(false);
    };
    const cls = horizontal ? 'resizing-row' : 'resizing-col';
    document.body.classList.add(cls);
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', end);
    window.addEventListener('pointercancel', end);
    return () => {
      document.body.classList.remove(cls);
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', end);
      window.removeEventListener('pointercancel', end);
    };
  }, [dragging, horizontal]);

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    e.preventDefault();
    origin.current = { pos: horizontal ? e.clientY : e.clientX, value };
    setDragging(true);
  };

  const clamp = (v: number) => Math.round(Math.min(max, Math.max(min, v)));
  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const step = e.shiftKey ? 64 : 16;
    const grow = horizontal ? (invert ? 'ArrowUp' : 'ArrowDown') : invert ? 'ArrowLeft' : 'ArrowRight';
    const shrink = horizontal ? (invert ? 'ArrowDown' : 'ArrowUp') : invert ? 'ArrowRight' : 'ArrowLeft';
    if (e.key === grow) onChange(clamp(value + step));
    else if (e.key === shrink) onChange(clamp(value - step));
    else if (e.key === 'Home') onChange(min);
    else if (e.key === 'End') onChange(max);
    else return;
    e.preventDefault();
  };

  return (
    <div
      role="separator"
      aria-orientation={horizontal ? 'horizontal' : 'vertical'}
      aria-label={label}
      aria-valuenow={Math.round(value)}
      aria-valuemin={Math.round(min)}
      aria-valuemax={Math.round(max)}
      tabIndex={0}
      className={`splitter ${orientation}${dragging ? ' dragging' : ''}`}
      onPointerDown={onPointerDown}
      onDoubleClick={onReset}
      onKeyDown={onKeyDown}
    />
  );
};
