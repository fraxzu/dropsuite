import { useCallback, useEffect, useRef, useState } from 'react';
import { RepeaterAttemptRecord, RepeaterTabRecord, ReplayFailure, ReplayResponse, TransactionRecord } from '../types';
import { draftFromRecord, NEW_DRAFT, parseHeaderLines, ReplayDraft } from './replay';
import { repeater, replay } from './transport';

/** Open Replay tabs at most; each keeps at most MAX_ATTEMPTS sanitized responses. */
export const MAX_TABS = 16;
export const MAX_ATTEMPTS = 20;

export const TAB_COLORS = [
  { id: 'gray', label: 'Default', hex: '#6b7280' },
  { id: 'red', label: 'Red', hex: '#ef4444' },
  { id: 'orange', label: 'Orange', hex: '#f97316' },
  { id: 'yellow', label: 'Yellow', hex: '#eab308' },
  { id: 'green', label: 'Green', hex: '#22c55e' },
  { id: 'blue', label: 'Blue', hex: '#3b82f6' },
  { id: 'purple', label: 'Purple', hex: '#a855f7' },
] as const;

/** One manual send: the sanitized response (or the failure), never the typed values. */
export interface Attempt {
  seq: number;
  at: number;
  method: string;
  destination: string;
  response?: ReplayResponse;
  failure?: ReplayFailure;
}

export interface ReplayTab {
  id: number;
  name: string;
  color?: string | null;
  groupName?: string | null;
  draft: ReplayDraft;
  attempts: Attempt[];
  /** The attempt on screen; null shows the latest. */
  viewSeq: number | null;
  nextSeq: number;
}

export interface Inflight {
  tabId: number;
  destination: string;
}

const MAX_NAME = 40;

function pathOf(url: string): string {
  const m = /^[a-z]+:\/\/[^/?#]*([^#]*)/i.exec(url);
  return (m?.[1] || '/').split('?')[0];
}

function mapAttemptRecord(rec: RepeaterAttemptRecord): Attempt {
  if (rec.failure_kind) {
    return {
      seq: rec.seq,
      at: rec.created_at,
      method: rec.method,
      destination: rec.destination,
      failure: {
        kind: rec.failure_kind,
        message: rec.failure_message ?? '',
      },
    };
  }
  return {
    seq: rec.seq,
    at: rec.created_at,
    method: rec.method,
    destination: rec.destination,
    response: {
      status: rec.status_code ?? 200,
      reason: '',
      headers: rec.response_headers ?? [],
      message: rec.response_body ?? [],
      content_type: rec.content_type,
      total_bytes: rec.total_bytes,
      sent_bytes: rec.sent_bytes,
      duration_ms: rec.duration_ms,
      destination: rec.destination,
      dropped_headers: [],
      request_target: '',
      request_headers: [],
      request_message: [],
      // Stored attempts do not keep the challenge flag, so a reopened session shows none.
      challenge: null,
    },
  };
}

/**
 * Replay sessions are backed by SQLite storage so tabs, drafts, custom colors,
 * groups, and past attempts persist across application restarts.
 */
export function useReplaySessions() {
  const nextId = useRef(2);
  const [tabs, setTabs] = useState<ReplayTab[]>(() => [
    { id: 1, name: 'Request 1', color: null, groupName: null, draft: { ...NEW_DRAFT }, attempts: [], viewSeq: null, nextSeq: 1 },
  ]);
  const [activeId, setActiveId] = useState(1);
  const [inflight, setInflight] = useState<Inflight | null>(null);
  const inflightRef = useRef<Inflight | null>(null);
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;

  const saveTimers = useRef<Record<number, ReturnType<typeof setTimeout>>>({});

  const debouncePersistTab = useCallback((tab: ReplayTab) => {
    if (saveTimers.current[tab.id]) {
      clearTimeout(saveTimers.current[tab.id]);
    }
    saveTimers.current[tab.id] = setTimeout(() => {
      const parsed = parseHeaderLines(tab.draft.headersText);
      const record: RepeaterTabRecord = {
        id: tab.id,
        name: tab.name,
        color: tab.color ?? null,
        group_name: tab.groupName ?? null,
        method: tab.draft.method,
        url: tab.draft.url,
        headers: parsed.headers,
        body: tab.draft.body,
        created_at: 0,
        updated_at: Date.now(),
      };
      repeater.saveTab(record).catch(() => {});
    }, 400);
  }, []);

  // Hydrate tabs from SQLite database on mount
  useEffect(() => {
    let cancelled = false;
    repeater
      .getTabs()
      .then(async (dbTabs) => {
        if (cancelled || !dbTabs || dbTabs.length === 0) return;
        const loaded: ReplayTab[] = [];
        let maxId = 1;

        for (const t of dbTabs) {
          if (t.id > maxId) maxId = t.id;
          const headersText = (t.headers || []).map(([k, v]) => `${k}: ${v}`).join('\n');
          let attempts: Attempt[] = [];
          try {
            const dbAttempts = await repeater.listAttempts(t.id, MAX_ATTEMPTS);
            attempts = (dbAttempts || []).map(mapAttemptRecord);
          } catch {
            // Non-critical if attempts fetch fails
          }
          const maxSeq = attempts.reduce((max, a) => Math.max(max, a.seq), 0);
          loaded.push({
            id: t.id,
            name: t.name,
            color: t.color ?? null,
            groupName: t.group_name ?? null,
            draft: {
              method: t.method || 'GET',
              url: t.url || 'http://',
              headersText: headersText || 'Accept: */*\nUser-Agent: DropSuite/0.1',
              body: t.body || '',
            },
            attempts,
            viewSeq: null,
            nextSeq: maxSeq + 1,
          });
        }

        if (!cancelled && loaded.length > 0) {
          nextId.current = maxId + 1;
          setTabs(loaded);
          setActiveId(loaded[0].id);
        }
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, []);

  const update = useCallback(
    (id: number, fn: (t: ReplayTab) => ReplayTab) => {
      setTabs((all) =>
        all.map((t) => {
          if (t.id === id) {
            const updated = fn(t);
            debouncePersistTab(updated);
            return updated;
          }
          return t;
        }),
      );
    },
    [debouncePersistTab],
  );

  /** Open a new tab; false when the tab limit is reached. */
  const open = useCallback(
    (draft: ReplayDraft, name?: string, color?: string | null, groupName?: string | null): boolean => {
      if (tabsRef.current.length >= MAX_TABS) return false;
      const id = nextId.current++;
      const tab: ReplayTab = {
        id,
        name: (name ?? `Request ${id}`).slice(0, MAX_NAME),
        color: color ?? null,
        groupName: groupName ?? null,
        draft,
        attempts: [],
        viewSeq: null,
        nextSeq: 1,
      };
      setTabs((all) => [...all, tab]);
      setActiveId(id);
      debouncePersistTab(tab);
      return true;
    },
    [debouncePersistTab],
  );

  const openFromRecord = useCallback(
    (record: TransactionRecord) =>
      open(draftFromRecord(record), `#${record.id} ${record.method.toUpperCase()} ${pathOf(record.url)}`),
    [open],
  );

  const close = useCallback(
    (id: number) => {
      const all = tabsRef.current;
      const i = all.findIndex((t) => t.id === id);
      if (i === -1) return;
      repeater.deleteTab(id).catch(() => {});
      const rest = all.filter((t) => t.id !== id);
      if (rest.length === 0) {
        const fresh = nextId.current++;
        const freshTab: ReplayTab = {
          id: fresh,
          name: `Request ${fresh}`,
          color: null,
          groupName: null,
          draft: { ...NEW_DRAFT },
          attempts: [],
          viewSeq: null,
          nextSeq: 1,
        };
        setTabs([freshTab]);
        setActiveId(fresh);
        debouncePersistTab(freshTab);
        return;
      }
      setTabs(rest);
      setActiveId((cur) => (cur === id ? rest[Math.min(i, rest.length - 1)].id : cur));
    },
    [debouncePersistTab],
  );

  const rename = useCallback(
    (id: number, name: string) => {
      const clean = name.replace(/\s+/g, ' ').trim().slice(0, MAX_NAME);
      if (clean) update(id, (t) => ({ ...t, name: clean }));
    },
    [update],
  );

  const setColor = useCallback(
    (id: number, color: string | null) => {
      update(id, (t) => ({ ...t, color }));
    },
    [update],
  );

  const setGroup = useCallback(
    (id: number, groupName: string | null) => {
      update(id, (t) => ({ ...t, groupName }));
    },
    [update],
  );

  /** Copy the editor of a tab into a new tab. Its responses are not copied and nothing is sent. */
  const duplicate = useCallback(
    (id: number): boolean => {
      const src = tabsRef.current.find((t) => t.id === id);
      return !!src && open({ ...src.draft }, `${src.name} copy`, src.color, src.groupName);
    },
    [open],
  );

  const setDraft = useCallback((id: number, draft: ReplayDraft) => update(id, (t) => ({ ...t, draft })), [update]);
  const view = useCallback((id: number, seq: number | null) => update(id, (t) => ({ ...t, viewSeq: seq })), [update]);

  /** Send once, on the user's click. One request in flight across all tabs. */
  const send = useCallback(
    async (
      id: number,
      request: { method: string; url: string; headers: [string, string][]; body: string },
      destination: string,
    ) => {
      if (inflightRef.current) return;
      inflightRef.current = { tabId: id, destination };
      setInflight(inflightRef.current);
      let outcome: Pick<Attempt, 'response' | 'failure'>;
      try {
        outcome = { response: await replay.send(request) };
      } catch (e) {
        outcome = { failure: e as ReplayFailure };
      } finally {
        inflightRef.current = null;
        setInflight(null);
      }
      update(id, (t) => {
        const attempt: Attempt = {
          seq: t.nextSeq,
          at: Date.now(),
          method: request.method,
          destination,
          ...outcome,
        };

        // Persist attempt to SQLite database asynchronously
        const attemptRecord: RepeaterAttemptRecord = {
          id: 0,
          tab_id: id,
          seq: attempt.seq,
          created_at: attempt.at,
          method: attempt.method,
          destination: attempt.destination,
          status_code: outcome.response?.status ?? null,
          duration_ms: outcome.response?.duration_ms ?? 0,
          total_bytes: outcome.response?.total_bytes ?? 0,
          sent_bytes: outcome.response?.sent_bytes ?? 0,
          response_headers: outcome.response?.headers ?? [],
          response_body: outcome.response?.message ?? [],
          content_type: outcome.response?.content_type ?? null,
          failure_kind: outcome.failure?.kind ?? null,
          failure_message: outcome.failure?.message ?? null,
        };
        repeater.saveAttempt(attemptRecord).catch(() => {});

        return {
          ...t,
          attempts: [...t.attempts, attempt].slice(-MAX_ATTEMPTS),
          nextSeq: t.nextSeq + 1,
          viewSeq: null,
        };
      });
    },
    [update],
  );

  return {
    tabs,
    activeId,
    setActiveId,
    inflight,
    open,
    openFromRecord,
    close,
    rename,
    setColor,
    setGroup,
    duplicate,
    setDraft,
    view,
    send,
    cancel: replay.cancel,
  };
}

export type ReplaySessions = ReturnType<typeof useReplaySessions>;
