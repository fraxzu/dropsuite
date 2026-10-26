import React, { useEffect, useState } from 'react';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { Copy, Minus, Square, X } from 'lucide-react';

/**
 * Minimize, maximize/restore and close for the frameless desktop window. The chrome bar is the
 * drag region (double-click maximizes); the window edges stay resizable.
 */
export const WindowControls: React.FC = () => {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    const win = getCurrentWindow();
    let unlisten: (() => void) | undefined;
    let alive = true;
    const sync = () => win.isMaximized().then((m) => alive && setMaximized(m)).catch(() => {});
    sync();
    win
      .onResized(sync)
      .then((u) => (alive ? (unlisten = u) : u()))
      .catch(() => {});
    return () => {
      alive = false;
      unlisten?.();
    };
  }, []);

  const win = getCurrentWindow();
  return (
    <div className="window-controls" role="group" aria-label="Window">
      <button className="win-btn" aria-label="Minimize" title="Minimize" onClick={() => win.minimize()}>
        <Minus size={15} strokeWidth={1.5} />
      </button>
      <button
        className="win-btn"
        aria-label={maximized ? 'Restore' : 'Maximize'}
        title={maximized ? 'Restore' : 'Maximize'}
        onClick={() => win.toggleMaximize()}
      >
        {maximized ? <Copy size={12} strokeWidth={1.5} style={{ transform: 'scaleX(-1)' }} /> : <Square size={11} strokeWidth={1.5} />}
      </button>
      <button className="win-btn win-close" aria-label="Close" title="Close" onClick={() => win.close()}>
        <X size={16} strokeWidth={1.5} />
      </button>
    </div>
  );
};
