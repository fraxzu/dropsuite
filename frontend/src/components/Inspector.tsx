import React, { useLayoutEffect, useRef, useState } from 'react';
import { AlertTriangle, Check, Columns2, Link2, PanelTop, Repeat, RotateCw, Sparkles } from 'lucide-react';
import { TransactionRecord, TransactionSummary } from '../types';
import { DetailState } from '../lib/api';
import { bytesToText, copyText, displayPath, formatBytes, formatDateTime, formatDuration, statusClass } from '../lib/http';
import { useStoredState } from '../lib/useStoredState';
import { MessagePane, Side } from './MessagePane';
import { AnalyzeModal } from './AnalyzeModal';
import { Splitter } from './Splitter';

function messageText(method: string, url: string, status: number, headers: [string, string][], body: number[], isRequest: boolean): string {
  const line = isRequest ? `${method} ${url} HTTP/1.1` : `HTTP/1.1 ${status}`;
  const head = `${line}\n${headers.map(([k, v]) => `${k}: ${v}`).join('\n')}`;
  return body.length ? `${head}\n\n${bytesToText(new Uint8Array(body))}` : head;
}

interface InspectorProps {
  summary: TransactionSummary | null;
  detail: DetailState;
  onRetry: () => void;
  onCopied: (what: string) => void;
  /** Copy the (sanitized) request into the Replay editor. Never sends. */
  onSendToReplay?: (record: TransactionRecord) => void;
}

const MIN_PANE = 260;
const TABBED_BELOW = 760;

export const Inspector: React.FC<InspectorProps> = ({ summary, detail, onRetry, onCopied, onSendToReplay }) => {
  const [layout, setLayout] = useStoredState<'split' | 'tabs'>('inspector.layout', 'split');
  const [side, setSide] = useStoredState<Side>('inspector.side', 'request');
  const [ratio, setRatio] = useStoredState<number>('inspector.ratio', 0.5);
  const [urlCopied, setUrlCopied] = useState(false);
  const [analyze, setAnalyze] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(1200);

  useLayoutEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    setWidth(el.clientWidth);
    return () => ro.disconnect();
  }, [summary === null]);

  if (!summary) {
    return (
      <div className="inspector">
        <div className="insp-empty">
          <span className="title">No request selected</span>
          <span>
            Select a row in the history, or press <kbd>j</kbd> / <kbd>k</kbd> to step through it.
          </span>
        </div>
      </div>
    );
  }

  const record = detail.kind === 'ready' && detail.record.id === summary.id ? detail.record : null;
  const url = record?.url ?? summary.path;
  const tabbed = layout === 'tabs' || width < TABBED_BELOW;
  const reqPx = Math.min(width - MIN_PANE, Math.max(MIN_PANE, width * ratio));

  const copyUrl = async () => {
    if (await copyText(url)) {
      setUrlCopied(true);
      onCopied('URL copied');
      setTimeout(() => setUrlCopied(false), 1200);
    }
  };

  const switcher = (
    <div className="msg-title switch" role="tablist" aria-label="Message">
      {(['request', 'response'] as Side[]).map((s) => (
        <button key={s} role="tab" aria-selected={side === s} onClick={() => setSide(s)}>
          {s === 'request' ? 'Request' : 'Response'}
        </button>
      ))}
    </div>
  );

  let body: React.ReactNode;
  if (detail.kind === 'error' && detail.id === summary.id) {
    body = (
      <div className="state error" role="alert">
        <h2>
          <AlertTriangle size={16} /> Couldn't load request #{summary.id}
        </h2>
        <p>{detail.message}</p>
        <div className="actions">
          <button className="btn" onClick={onRetry}>
            <RotateCw size={12} /> Try again
          </button>
        </div>
      </div>
    );
  } else if (!record) {
    body = (
      <div className="msg" aria-busy="true">
        <div className="msg-head" />
        {Array.from({ length: 7 }, (_, i) => (
          <div key={i} className="skeleton-row">
            <span className="skeleton-bar" style={{ width: 120 + ((i * 53) % 240) }} />
          </div>
        ))}
      </div>
    );
  } else if (tabbed) {
    body = <MessagePane key={`${record.id}-${side}`} side={side} record={record} title={switcher} onCopied={onCopied} />;
  } else {
    body = (
      <>
        <div className="pane" style={{ width: reqPx, flexShrink: 0 }}>
          <MessagePane key={`${record.id}-req`} side="request" record={record} title={<span className="msg-title">Request</span>} onCopied={onCopied} />
        </div>
        <Splitter
          orientation="vertical"
          label="Resize request and response panes"
          value={reqPx}
          min={MIN_PANE}
          max={width - MIN_PANE}
          onChange={(px) => setRatio(px / width)}
          onReset={() => setRatio(0.5)}
        />
        <div className="pane" style={{ flex: 1 }}>
          <MessagePane
            key={`${record.id}-res`}
            side="response"
            record={record}
            title={
              <span className="msg-title">
                Response
              </span>
            }
            onCopied={onCopied}
          />
        </div>
      </>
    );
  }

  return (
    <div className="inspector" aria-label={`Request ${summary.id}`} role="region">
      <div className="insp-head">
        <span className="method">{summary.method}</span>
        <span className="target" title={url}>
          <span className="path selectable">{displayPath(summary)}</span>
          <span className="host">{summary.host}</span>
        </span>
        <span className="insp-facts">
          <span className={`status ${statusClass(summary.status_code)}`}>{summary.status_code}</span>
          <span>{formatDuration(summary.duration_ms)}</span>
          <span>{formatBytes(summary.content_length)}</span>
          <span>{formatDateTime(summary.timestamp)}</span>
          <span className="mono" style={{ color: 'var(--text-3)' }}>
            #{summary.id}
          </span>
        </span>
        <span className="insp-tools">
          <button
            className="fz-pill fz-ai"
            disabled={!record}
            onClick={() => setAnalyze(true)}
            title="Ask Drop AI to review this request and response"
          >
            <Sparkles size={12} /> Analyze with AI
          </button>
          {onSendToReplay && (
            <button
              className="btn replay-send-to"
              disabled={!record}
              onClick={() => record && onSendToReplay(record)}
              title="Copy this request into Replay to edit and resend it (r). Nothing is sent until you press Send there."
            >
              <Repeat size={12} /> Send to Replay
            </button>
          )}
          <button className={`icon-btn${urlCopied ? ' done' : ''}`} onClick={copyUrl} aria-label="Copy full URL" title="Copy full URL">
            {urlCopied ? <Check size={14} /> : <Link2 size={14} />}
          </button>
          <button
            className="icon-btn"
            aria-pressed={!tabbed}
            disabled={width < TABBED_BELOW}
            onClick={() => setLayout('split')}
            aria-label="Request and response side by side"
            title={width < TABBED_BELOW ? 'Widen the window to show both side by side' : 'Side by side'}
          >
            <Columns2 size={14} />
          </button>
          <button className="icon-btn" aria-pressed={tabbed} onClick={() => setLayout('tabs')} aria-label="One message at a time" title="One at a time">
            <PanelTop size={14} />
          </button>
        </span>
      </div>
      <div className="insp-body" ref={bodyRef}>
        {body}
      </div>
      {analyze && record && (
        <AnalyzeModal
          requestText={messageText(record.method, record.url, record.status_code, record.request_headers, record.request_body, true)}
          responseText={messageText(record.method, record.url, record.status_code, record.response_headers, record.response_body, false)}
          contentType={record.content_type ?? undefined}
          onClose={() => setAnalyze(false)}
          onToast={onCopied}
        />
      )}
    </div>
  );
};
