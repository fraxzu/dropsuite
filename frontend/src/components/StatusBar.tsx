import React from 'react';
import { ProxyStatus } from '../types';
import { DESKTOP, ENGINE_LABEL } from '../lib/transport';

interface StatusBarProps {
  status: ProxyStatus | null;
  connected: boolean | null;
  loaded: number;
}

export const StatusBar: React.FC<StatusBarProps> = ({ status, connected, loaded }) => {
  const total = status?.total_captured ?? 0;
  return (
    <footer className="statusbar">
      <span className="item">
        <span className={`dot ${connected === false ? 'error' : status?.is_running ? 'live' : 'off'}`} />
        {connected === false ? (DESKTOP ? 'Engine unavailable' : 'Daemon unreachable · retrying') : status?.is_running ? 'Listening' : status ? 'Listener stopped' : 'Connecting…'}
      </span>
      {status && (
        <span className="item">
          <strong>{total.toLocaleString()}</strong> captured
          {total > loaded && loaded > 0 && <span>· latest {loaded.toLocaleString()} loaded</span>}
        </span>
      )}
      <span className="item">Stored locally</span>
      <span className="spacer" />
      <span className="keys" aria-hidden="true">
        <span>
          <kbd>j</kbd> <kbd>k</kbd> move
        </span>
        <span>
          <kbd>/</kbd> search
        </span>
        <span>
          <kbd>b</kbd> scope to burst
        </span>
        <span>
          <kbd>Esc</kbd> clear
        </span>
      </span>
      <span className={`item${DESKTOP ? '' : ' mono'}`}>{ENGINE_LABEL}</span>
    </footer>
  );
};
