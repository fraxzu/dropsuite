import { useCallback, useEffect, useRef, useState } from 'react';
import { ProxyStatus, TransactionRecord, TransactionSummary } from '../types';
import { engine } from './transport';

const POLL_MS = 1500;

/**
 * Listener status and engine reachability. `connected` is null until the first round trip
 * resolves; `error` carries the engine's own explanation when it is unavailable.
 */
export function useDaemonStatus() {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [connected, setConnected] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const last = useRef('');

  const poll = useCallback(async () => {
    try {
      const next = await engine.status();
      const text = JSON.stringify(next);
      if (text !== last.current) {
        last.current = text;
        setStatus(next);
      }
      setConnected(true);
      setError(null);
    } catch (e) {
      setConnected(false);
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    poll();
    const t = setInterval(poll, POLL_MS);
    return () => clearInterval(t);
  }, [poll]);

  /** Throws with the engine's message (for example, the port is already in use). */
  const setRunning = useCallback(
    async (run: boolean) => {
      try {
        await engine.setRunning(run);
      } finally {
        await poll();
      }
    },
    [poll],
  );

  return { status, connected, error, setRunning, refresh: poll };
}

export interface HistoryQuery {
  q: string;
  method: string;
}

/**
 * Polls history with the engine's own `q` / `method` filters.
 * Returns null until the first response for the current query arrives.
 */
export function useHistory(query: HistoryQuery, enabled = true) {
  const [data, setData] = useState<{ key: string; items: TransactionSummary[] } | null>(null);
  const last = useRef('');
  const key = `${query.q}\u0000${query.method}`;
  const current = useRef(key);
  current.current = key;

  const poll = useCallback(async () => {
    try {
      const items = await engine.history(query.q, query.method);
      if (key !== current.current) return;
      const tagged = key + JSON.stringify(items);
      if (tagged !== last.current) {
        last.current = tagged;
        setData({ key, items });
      }
    } catch {
      /* reachability is reported by useDaemonStatus */
    }
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!enabled) return;
    poll();
    const t = setInterval(poll, POLL_MS);
    return () => clearInterval(t);
  }, [poll, enabled]);

  return {
    items: data?.items ?? null,
    /** False while the rows on screen belong to a previous query. */
    fresh: data?.key === key,
    refresh: poll,
  };
}

export type DetailState =
  | { kind: 'idle' }
  | { kind: 'loading'; id: number }
  | { kind: 'ready'; record: TransactionRecord }
  | { kind: 'error'; id: number; message: string };

const detailCache = new Map<number, TransactionRecord>();

/** Captured transactions never change, so detail records are cached for the session. */
export function useTransaction(id: number | null) {
  const [state, setState] = useState<DetailState>({ kind: 'idle' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (id === null) {
      setState({ kind: 'idle' });
      return;
    }
    const hit = detailCache.get(id);
    if (hit) {
      setState({ kind: 'ready', record: hit });
      return;
    }
    let live = true;
    setState({ kind: 'loading', id });
    engine
      .transaction(id)
      .then((record) => {
        detailCache.set(id, record);
        if (live) setState({ kind: 'ready', record });
      })
      .catch((e: unknown) => {
        if (live) setState({ kind: 'error', id, message: e instanceof Error ? e.message : String(e) });
      });
    return () => {
      live = false;
    };
  }, [id, attempt]);

  return { state, retry: () => setAttempt((n) => n + 1) };
}
