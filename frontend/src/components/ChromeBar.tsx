import React, { useCallback, useState } from 'react';
import { Play, Square, Loader2, Settings2, Sparkles, CircleHelp, Settings } from 'lucide-react';
import { ProxyStatus } from '../types';
import { BrandMark } from './BrandMark';
import { DESKTOP } from '../lib/transport';
import { ListenerSettingsPanel } from './ListenerSettingsPanel';
import { DropAiPanel } from './DropAiPanel';
import { HelpGuide } from './HelpGuide';
import { AboutPanel } from './AboutPanel';
import { WindowControls } from './WindowControls';

export type Workspace = 'proxy' | 'target' | 'replay' | 'fuzzer' | 'decoder' | 'comparer' | 'scanner';

interface ChromeBarProps {
  workspace: Workspace;
  onWorkspace: (w: Workspace) => void;
  status: ProxyStatus | null;
  connected: boolean | null;
  toggling: boolean;
  onToggleProxy: () => void;
  onPortSaved: (port: number) => void;
  onToast?: (msg: string) => void;
}


export const ChromeBar: React.FC<ChromeBarProps> = ({ workspace, onWorkspace, status, connected, toggling, onToggleProxy, onPortSaved, onToast }) => {
  const running = !!status?.is_running;
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [aiOpen, setAiOpen] = useState(false);
  const [guideOpen, setGuideOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const closeSettings = useCallback(() => setSettingsOpen(false), []);
  const closeAi = useCallback(() => setAiOpen(false), []);
  const addr = status ? `${status.bind_address}:${status.port}` : '127.0.0.1:8080';

  let state: React.ReactNode;
  if (connected === false) {
    state = (
      <>
        <span className="dot error" />
        {DESKTOP ? 'Engine unavailable' : 'Daemon unreachable'}
      </>
    );
  } else if (!status) {
    state = (
      <>
        <span className="dot off" />
        Connecting…
      </>
    );
  } else if (running) {
    state = (
      <>
        <span className="dot live" />
        Listening on <span className="addr">{addr}</span>
      </>
    );
  } else {
    state = (
      <>
        <span className="dot off" />
        Listener stopped
      </>
    );
  }

  return (
    // In the desktop app the bar is the window's title bar: empty areas drag the window and a
    // double-click maximizes; buttons and the settings panel keep their own clicks.
    <header className={`chrome${DESKTOP ? ' desktop' : ''}`} data-tauri-drag-region={DESKTOP ? 'deep' : undefined}>
      <div className="brand">
        <BrandMark />
        <span className="brand-name">DropSuite</span>
        <span className="brand-version">0.1.0</span>
      </div>

      <nav className="workspaces" aria-label="Workspaces">
        <button className="ws-tab" aria-current={workspace === 'proxy' ? 'page' : undefined} onClick={() => onWorkspace('proxy')} title="Proxy (Alt+1)">
          Proxy
        </button>
        <button className="ws-tab" aria-current={workspace === 'target' ? 'page' : undefined} onClick={() => onWorkspace('target')} title="Target site map (Alt+2)">
          Target
        </button>
        <button className="ws-tab" aria-current={workspace === 'replay' ? 'page' : undefined} onClick={() => onWorkspace('replay')} title="Replay: edit and resend a request (Alt+3)">
          Replay
        </button>
        <button className="ws-tab" aria-current={workspace === 'fuzzer' ? 'page' : undefined} onClick={() => onWorkspace('fuzzer')} title="Fuzzer: automated payload testing (Alt+4)">
          Fuzzer
        </button>
        <button className="ws-tab" aria-current={workspace === 'decoder' ? 'page' : undefined} onClick={() => onWorkspace('decoder')} title="Decoder: encode and decode text (Alt+5)">
          Decoder
        </button>
        <button className="ws-tab" aria-current={workspace === 'comparer' ? 'page' : undefined} onClick={() => onWorkspace('comparer')} title="Comparer: diff two texts (Alt+6)">
          Comparer
        </button>
        <span className="ws-divider" aria-hidden="true" />
        <button className="ws-tab" aria-current={workspace === 'scanner' ? 'page' : undefined} onClick={() => onWorkspace('scanner')} title="Scanner: passive issues across captured traffic (Alt+7)">
          Scanner
        </button>
      </nav>

      <div className="chrome-spacer" />

      <div className="listener">
        <span className="listener-state" role="status" aria-live="polite">
          {state}
        </span>
        <button className="icon-btn" aria-label="Guide" title="How to use DropSuite" onClick={() => setGuideOpen(true)}>
          <CircleHelp size={15} aria-hidden="true" />
        </button>
        {DESKTOP && (
          <button className="icon-btn" aria-label="Settings and about" title="Settings & about: version, updates, logs" onClick={() => setAboutOpen(true)}>
            <Settings size={15} aria-hidden="true" />
          </button>
        )}
        <button
          className={`btn ${running ? 'btn-stop' : 'btn-primary'}`}
          onClick={onToggleProxy}
          disabled={!status || connected === false || toggling}
          aria-label={running ? 'Stop proxy listener' : 'Start proxy listener'}
        >
          {toggling ? <Loader2 size={13} className="spin" /> : running ? <Square size={11} fill="currentColor" /> : <Play size={12} fill="currentColor" />}
          {toggling ? (running ? 'Stopping' : 'Starting') : running ? 'Stop' : 'Start'}
        </button>
        {DESKTOP && (
          <button
            className="icon-btn labeled"
            data-dropai-toggle
            aria-label="Drop AI settings"
            aria-expanded={aiOpen}
            aria-haspopup="dialog"
            title="Drop AI: bring your own model and key"
            disabled={connected === false}
            onClick={() => {
              setSettingsOpen(false);
              setAiOpen((o) => !o);
            }}
          >
            <Sparkles size={14} aria-hidden="true" />
            <span aria-hidden="true">Drop AI</span>
          </button>
        )}
        {aiOpen && <DropAiPanel onClose={closeAi} onToast={onToast} />}
        {/* Configures only the proxy listener, not the app, so it carries a visible name. */}
        {DESKTOP && (
          <button
            className="icon-btn labeled"
            data-settings-toggle
            aria-label="Listener settings"
            aria-describedby="listener-settings-desc"
            aria-expanded={settingsOpen}
            aria-haspopup="dialog"
            title={`Listener settings: address, port, and log folder (now ${addr})`}
            disabled={connected === false}
            onClick={() => {
              setAiOpen(false);
              setSettingsOpen((o) => !o);
            }}
          >
            <Settings2 size={14} aria-hidden="true" />
            <span aria-hidden="true">Listener</span>
          </button>
        )}
        {DESKTOP && (
          <span id="listener-settings-desc" className="visually-hidden">
            Configure the proxy listener address, port, and log folder.
          </span>
        )}
        {settingsOpen && (
          <ListenerSettingsPanel
            running={running}
            onClose={closeSettings}
            onSaved={(port) => {
              setSettingsOpen(false);
              onPortSaved(port);
            }}
            onToast={onToast}
          />
        )}
      </div>
      {DESKTOP && <WindowControls />}
      {guideOpen && <HelpGuide onClose={() => setGuideOpen(false)} />}
      {aboutOpen && <AboutPanel onClose={() => setAboutOpen(false)} onToast={onToast} />}
    </header>
  );
};
