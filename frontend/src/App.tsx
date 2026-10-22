import { useCallback, useEffect, useRef, useState } from 'react';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { ChromeBar, Workspace } from './components/ChromeBar';
import { StatusBar } from './components/StatusBar';
import { useDaemonStatus } from './lib/api';
import { DESKTOP } from './lib/transport';
import { useStoredState } from './lib/useStoredState';
import { ProxyWorkspace } from './workspaces/ProxyWorkspace';
import { TargetWorkspace } from './workspaces/TargetWorkspace';
import { ReplayWorkspace } from './workspaces/ReplayWorkspace';
import { FuzzerWorkspace } from './workspaces/FuzzerWorkspace';
import { DecoderWorkspace } from './workspaces/DecoderWorkspace';
import { ComparerWorkspace } from './workspaces/ComparerWorkspace';
import { ScannerWorkspace } from './workspaces/ScannerWorkspace';
import { MAX_TABS, useReplaySessions } from './lib/replaySessions';
import { ReplayDraft } from './lib/replay';
import { TransactionRecord } from './types';

export function App() {
  const { status, connected, error, setRunning, refresh } = useDaemonStatus();
  const [workspace, setWorkspace] = useStoredState<Workspace>('workspace', 'proxy');
  const [toggling, setToggling] = useState(false);
  const [loaded, setLoaded] = useState(0);
  const [toast, setToast] = useState<string | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout>>();
  const maximizedBeforeFullscreen = useRef(false);
  // Replay tabs live in memory only: they can hold credentials the user typed.
  const replaySessions = useReplaySessions();

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), msg.length > 60 ? 4000 : 1600);
  }, []);

  const sendToReplay = useCallback(
    (record: TransactionRecord) => {
      if (!replaySessions.openFromRecord(record)) {
        showToast(`Close a Replay tab first (at most ${MAX_TABS} are open).`);
        return;
      }
      setWorkspace('replay');
      showToast(`Request #${record.id} opened in a new Replay tab. Nothing has been sent.`);
    },
    [replaySessions, setWorkspace, showToast],
  );

  const openDraftInReplay = useCallback(
    (draft: ReplayDraft, label: string) => {
      if (!replaySessions.open(draft, label)) {
        showToast(`Close a Replay tab first (at most ${MAX_TABS} are open).`);
        return;
      }
      setWorkspace('replay');
      showToast(`${label} opened in a new Replay tab. Nothing has been sent.`);
    },
    [replaySessions, setWorkspace, showToast],
  );

  const toggleProxy = async () => {
    if (!status) return;
    setToggling(true);
    try {
      await setRunning(!status.is_running);
    } catch (e) {
      showToast(`Couldn't ${status.is_running ? 'stop' : 'start'} the listener. ${e instanceof Error ? e.message : ''}`.trim());
    } finally {
      setToggling(false);
    }
  };

  // In the desktop app, browser reload and print shortcuts would discard the session or open
  // a print dialog for an application window; swallow them there.
  useEffect(() => {
    if (!DESKTOP) return;
    const onKey = (e: KeyboardEvent) => {
      const k = e.key.toLowerCase();
      if (e.key === 'F5' || ((e.ctrlKey || e.metaKey) && (k === 'r' || k === 'p'))) e.preventDefault();
      // F11 toggles full screen. A maximized window must be restored first (Windows will not
      // switch a maximized window to full screen) and is maximized again on the way back.
      if (e.key === 'F11') {
        e.preventDefault();
        const win = getCurrentWindow();
        (async () => {
          if (await win.isFullscreen()) {
            await win.setFullscreen(false);
            if (maximizedBeforeFullscreen.current) await win.maximize();
          } else {
            maximizedBeforeFullscreen.current = await win.isMaximized();
            if (maximizedBeforeFullscreen.current) await win.unmaximize();
            await win.setFullscreen(true);
          }
        })().catch(() => {});
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.altKey || e.ctrlKey || e.metaKey) return;
      if (e.key === '1') setWorkspace('proxy');
      else if (e.key === '2') setWorkspace('target');
      else if (e.key === '3') setWorkspace('replay');
      else if (e.key === '4') setWorkspace('fuzzer');
      else if (e.key === '5') setWorkspace('decoder');
      else if (e.key === '6') setWorkspace('comparer');
      else if (e.key === '7') setWorkspace('scanner');
      else return;
      e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [setWorkspace]);

  return (
    <div className="app">
      <ChromeBar
        workspace={workspace}
        onWorkspace={setWorkspace}
        status={status}
        connected={connected}
        toggling={toggling}
        onToggleProxy={toggleProxy}
        onPortSaved={(port) => {
          refresh();
          showToast(`Listener port set to ${port}. Start the listener to use it.`);
        }}
        onToast={showToast}
      />
      <main style={{ display: 'flex', minHeight: 0, minWidth: 0 }}>
        <ProxyWorkspace
          active={workspace === 'proxy'}
          status={status}
          connected={connected}
          engineError={error}
          onLoaded={setLoaded}
          onToast={showToast}
          onSendToReplay={sendToReplay}
        />
        <TargetWorkspace active={workspace === 'target'} status={status} connected={connected} onToast={showToast} onSendToReplay={sendToReplay} />
        <ReplayWorkspace active={workspace === 'replay'} sessions={replaySessions} onToast={showToast} />
        <FuzzerWorkspace active={workspace === 'fuzzer'} onToast={showToast} onSendToReplay={openDraftInReplay} />
        <DecoderWorkspace active={workspace === 'decoder'} onToast={showToast} />
        <ComparerWorkspace active={workspace === 'comparer'} onToast={showToast} />
        <ScannerWorkspace active={workspace === 'scanner'} onToast={showToast} onSendToReplay={openDraftInReplay} />
      </main>
      <StatusBar status={status} connected={connected} loaded={loaded} />
      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </div>
  );
}

export default App;
