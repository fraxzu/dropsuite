import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  FastForward,
  Play,
  Square,
  Trash2,
} from 'lucide-react';
import { InterceptStatus, InterceptedMessage } from '../types';
import { engine } from '../lib/transport';

interface InterceptPanelProps {
  active: boolean;
  onToast: (msg: string) => void;
  onQueueCountChange?: (count: number) => void;
}

export const InterceptPanel: React.FC<InterceptPanelProps> = ({
  active,
  onToast,
  onQueueCountChange,
}) => {
  const [status, setStatus] = useState<InterceptStatus>({
    enabled: false,
    intercept_requests: true,
    intercept_responses: false,
    queue_len: 0,
  });
  const [messages, setMessages] = useState<InterceptedMessage[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [draftWire, setDraftWire] = useState('');
  const lastLoadedId = useRef<number | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      const st = await engine.getInterceptStatus();
      setStatus(st);
      onQueueCountChange?.(st.queue_len);
    } catch {
      // ignore
    }
  }, [onQueueCountChange]);

  const refreshMessages = useCallback(async () => {
    try {
      const list = await engine.listInterceptedMessages();
      setMessages(list);
      onQueueCountChange?.(list.length);
      setStatus((s) => ({ ...s, queue_len: list.length }));
    } catch {
      // ignore
    }
  }, [onQueueCountChange]);

  // Fast poll when intercept is enabled, slower when off
  useEffect(() => {
    if (!active) return;
    refreshStatus();
    refreshMessages();
    const intervalMs = status.enabled ? 400 : 1500;
    const timer = setInterval(() => {
      refreshStatus();
      refreshMessages();
    }, intervalMs);
    return () => clearInterval(timer);
  }, [active, status.enabled, refreshStatus, refreshMessages]);

  // Synchronize draft wire when current message changes
  useEffect(() => {
    if (messages.length === 0) {
      lastLoadedId.current = null;
      setDraftWire('');
      setCurrentIndex(0);
      return;
    }
    const idx = Math.min(currentIndex, messages.length - 1);
    const curr = messages[idx];
    if (curr && curr.id !== lastLoadedId.current) {
      lastLoadedId.current = curr.id;
      setDraftWire(curr.raw_message);
    }
  }, [messages, currentIndex]);

  const currentMessage: InterceptedMessage | null =
    messages.length > 0
      ? messages[Math.min(currentIndex, messages.length - 1)]
      : null;

  const handleToggleEnabled = async () => {
    try {
      const next = await engine.setInterceptEnabled(!status.enabled);
      setStatus(next);
      onToast(
        next.enabled
          ? 'Intercept is ON: matching traffic will be paused.'
          : 'Intercept is OFF: traffic passes directly.',
      );
      await refreshMessages();
    } catch (e) {
      onToast(`Failed to toggle intercept: ${e}`);
    }
  };

  const handleToggleRequests = async () => {
    try {
      const next = await engine.setInterceptRequests(!status.intercept_requests);
      setStatus(next);
    } catch (e) {
      onToast(`Failed to update settings: ${e}`);
    }
  };

  const handleToggleResponses = async () => {
    try {
      const next = await engine.setInterceptResponses(
        !status.intercept_responses,
      );
      setStatus(next);
    } catch (e) {
      onToast(`Failed to update settings: ${e}`);
    }
  };

  const handleForward = useCallback(async () => {
    if (!currentMessage) return;
    const isModified = draftWire !== currentMessage.raw_message;
    try {
      await engine.forwardInterceptedMessage(
        currentMessage.id,
        isModified ? draftWire : undefined,
      );
      onToast(
        isModified
          ? `Forwarded request #${currentMessage.id} (edited)`
          : `Forwarded request #${currentMessage.id}`,
      );
      await refreshMessages();
    } catch (e) {
      onToast(`Forward error: ${e}`);
    }
  }, [currentMessage, draftWire, onToast, refreshMessages]);

  const handleDrop = useCallback(async () => {
    if (!currentMessage) return;
    try {
      await engine.dropInterceptedMessage(currentMessage.id);
      onToast(`Dropped request #${currentMessage.id}`);
      await refreshMessages();
    } catch (e) {
      onToast(`Drop error: ${e}`);
    }
  }, [currentMessage, onToast, refreshMessages]);

  const handleForwardAll = async () => {
    try {
      await engine.forwardAllIntercepted();
      onToast('Forwarded all held messages.');
      await refreshMessages();
    } catch (e) {
      onToast(`Error forwarding all: ${e}`);
    }
  };

  const handleDropAll = async () => {
    try {
      await engine.dropAllIntercepted();
      onToast('Dropped all held messages.');
      await refreshMessages();
    } catch (e) {
      onToast(`Error dropping all: ${e}`);
    }
  };

  // Keyboard shortcuts: Ctrl+F to forward, Ctrl+D to drop
  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        handleForward();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'd') {
        e.preventDefault();
        handleDrop();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [active, handleForward, handleDrop]);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        width: '100%',
        background: 'var(--ground)',
        overflow: 'hidden',
      }}
    >
      {/* Top Toolbar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '6px 12px',
          borderBottom: '1px solid var(--line)',
          background: 'var(--panel)',
          minHeight: 38,
          flexShrink: 0,
        }}
      >
        <button
          type="button"
          className="btn"
          onClick={handleToggleEnabled}
          style={{
            fontWeight: 600,
            background: status.enabled ? 'var(--sel)' : 'var(--ground)',
            borderColor: status.enabled ? 'var(--accent)' : 'var(--line)',
            color: status.enabled ? 'var(--accent-text)' : 'var(--text-2)',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          {status.enabled ? (
            <Play size={13} fill="currentColor" />
          ) : (
            <Square size={13} fill="currentColor" />
          )}
          {status.enabled ? 'Intercept is on' : 'Intercept is off'}
        </button>

        <span
          style={{ width: 1, height: 18, background: 'var(--line)', margin: '0 4px' }}
        />

        <button
          type="button"
          className="btn btn-primary"
          disabled={!currentMessage}
          onClick={handleForward}
          title="Forward message (Ctrl+F)"
        >
          Forward
        </button>

        <button
          type="button"
          className="btn"
          disabled={!currentMessage}
          onClick={handleDrop}
          style={{ color: currentMessage ? 'var(--danger)' : undefined }}
          title="Drop message (Ctrl+D)"
        >
          Drop
        </button>

        {messages.length > 1 && (
          <>
            <button
              type="button"
              className="btn"
              onClick={handleForwardAll}
              title="Forward all held messages"
              style={{ fontSize: 11 }}
            >
              <FastForward size={12} style={{ marginRight: 4 }} /> Forward all
            </button>
            <button
              type="button"
              className="btn"
              onClick={handleDropAll}
              title="Drop all held messages"
              style={{ fontSize: 11, color: 'var(--danger)' }}
            >
              <Trash2 size={12} style={{ marginRight: 4 }} /> Drop all
            </button>
          </>
        )}

        <span style={{ flex: 1 }} />

        {/* Options */}
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 5,
            fontSize: 11,
            color: 'var(--text-2)',
            cursor: 'pointer',
          }}
        >
          <input
            type="checkbox"
            checked={status.intercept_requests}
            onChange={handleToggleRequests}
          />
          Requests
        </label>

        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 5,
            fontSize: 11,
            color: 'var(--text-2)',
            cursor: 'pointer',
            marginRight: 8,
          }}
        >
          <input
            type="checkbox"
            checked={status.intercept_responses}
            onChange={handleToggleResponses}
          />
          Responses
        </label>

        {/* Queue Navigation */}
        {messages.length > 0 && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              fontSize: 11,
              color: 'var(--text-2)',
              background: 'var(--ground)',
              padding: '2px 8px',
              borderRadius: 'var(--radius)',
              border: '1px solid var(--line)',
            }}
          >
            <button
              type="button"
              disabled={currentIndex <= 0}
              onClick={() => setCurrentIndex((i) => Math.max(0, i - 1))}
              style={{
                background: 'none',
                border: 'none',
                color: currentIndex > 0 ? 'var(--text)' : 'var(--text-disabled)',
                cursor: currentIndex > 0 ? 'pointer' : 'default',
                padding: 0,
                display: 'flex',
              }}
            >
              <ChevronLeft size={14} />
            </button>
            <span style={{ margin: '0 4px', fontWeight: 600 }}>
              {Math.min(currentIndex + 1, messages.length)} of {messages.length}
            </span>
            <button
              type="button"
              disabled={currentIndex >= messages.length - 1}
              onClick={() =>
                setCurrentIndex((i) => Math.min(messages.length - 1, i + 1))
              }
              style={{
                background: 'none',
                border: 'none',
                color:
                  currentIndex < messages.length - 1
                    ? 'var(--text)'
                    : 'var(--text-disabled)',
                cursor:
                  currentIndex < messages.length - 1 ? 'pointer' : 'default',
                padding: 0,
                display: 'flex',
              }}
            >
              <ChevronRight size={14} />
            </button>
          </div>
        )}
      </div>

      {/* Target Details Bar (when a message is held) */}
      {currentMessage && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '6px 12px',
            borderBottom: '1px solid var(--line)',
            background: 'var(--ground)',
            fontSize: 12,
            fontFamily: 'var(--font-mono)',
          }}
        >
          <span
            style={{
              background:
                currentMessage.kind === 'response'
                  ? 'var(--s3)'
                  : 'var(--accent)',
              color: '#fff',
              padding: '1px 6px',
              borderRadius: 3,
              fontWeight: 700,
              fontSize: 10,
              textTransform: 'uppercase',
            }}
          >
            {currentMessage.kind}
          </span>

          <span style={{ fontWeight: 700, color: 'var(--text)' }}>
            {currentMessage.method}
          </span>

          {currentMessage.status_code && (
            <span style={{ color: 'var(--s2)', fontWeight: 600 }}>
              {currentMessage.status_code}
            </span>
          )}

          <span
            className="selectable"
            style={{
              color: 'var(--text-2)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              flex: 1,
            }}
          >
            {currentMessage.url}
          </span>

          <span style={{ fontSize: 11, color: 'var(--text-3)' }}>
            {currentMessage.body_len > 0
              ? `${currentMessage.body_len} bytes`
              : 'no body'}
          </span>
        </div>
      )}

      {/* Main Content: Raw HTTP Message Editor or Empty State */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', position: 'relative' }}>
        {currentMessage ? (
          <textarea
            aria-label="Intercepted raw HTTP message editor"
            spellCheck={false}
            value={draftWire}
            onChange={(e) => setDraftWire(e.target.value)}
            style={{
              width: '100%',
              height: '100%',
              background: 'var(--panel)',
              color: 'var(--text)',
              fontFamily: 'var(--font-mono)',
              fontSize: 12,
              lineHeight: '18px',
              padding: '10px 12px',
              border: 'none',
              outline: 'none',
              resize: 'none',
              whiteSpace: 'pre',
              overflowWrap: 'normal',
              overflowX: 'auto',
            }}
          />
        ) : (
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              width: '100%',
              height: '100%',
              color: 'var(--text-3)',
              gap: 12,
              userSelect: 'none',
            }}
          >
            {status.enabled ? (
              <>
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: '50%',
                    background: 'var(--sel-idle)',
                    border: '1px solid var(--accent)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent)',
                  }}
                >
                  <Play size={16} fill="currentColor" />
                </div>
                <div style={{ fontWeight: 600, color: 'var(--text)' }}>
                  Intercept is on
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-2)' }}>
                  Requests matching your rules will pause here for inspection
                  and editing.
                </div>
              </>
            ) : (
              <>
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: '50%',
                    background: 'var(--panel)',
                    border: '1px solid var(--line)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--text-disabled)',
                  }}
                >
                  <Square size={16} fill="currentColor" />
                </div>
                <div style={{ fontWeight: 600, color: 'var(--text-2)' }}>
                  Intercept is off
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
                  Traffic passes through the proxy without holding.
                </div>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleToggleEnabled}
                  style={{ marginTop: 8 }}
                >
                  Turn on intercept
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
