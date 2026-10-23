import { invoke, isTauri } from '@tauri-apps/api/core';
import {
  AppInfo,
  UpdateInfo,
  AttemptRow,
  DropAiConfig,
  DropAiStatus,
  HttpsSettings,
  ApplySettings,
  BrowserPreset,
  CookieRow,
  ImportOutcome,
  IntruderAttack,
  IntruderStatus,
  InterceptStatus,
  InterceptedMessage,
  ListenerSettings,
  MatchReplaceConfig,
  ProxyStatus,
  RepeaterAttemptRecord,
  RepeaterTabRecord,
  ReplayFailure,
  ReplayResponse,
  ScopeConfig,
  SiteNodeSummary,
  TransactionRecord,
  TransactionSummary,
} from '../types';

/**
 * How the interface reaches the capture engine.
 * - Desktop app: Tauri IPC into the in-process engine. No HTTP management API exists.
 * - Browser development: the headless dev daemon's loopback HTTP bridge.
 */
export const DESKTOP = isTauri();
export const DEV_API_BASE = (import.meta.env.VITE_DROPSUITE_API as string | undefined) ?? 'http://127.0.0.1:8081';

/** Short label for where the engine lives, shown in the status bar. */
export const ENGINE_LABEL = DESKTOP ? 'Local engine' : `API ${DEV_API_BASE.replace(/^https?:\/\//, '')}`;

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${DEV_API_BASE}${path}`, init);
  if (!res.ok) throw new Error(res.status === 404 ? 'DropSuite has no record with this ID.' : `The dev daemon answered ${res.status}.`);
  return (await res.json()) as T;
}

function message(e: unknown): string {
  if (typeof e === 'string') return e;
  if (e instanceof Error) return e.message === 'Failed to fetch' ? 'The dev daemon did not respond.' : e.message;
  return 'The capture engine did not respond.';
}

async function call<T>(desktop: () => Promise<T>, dev: () => Promise<T>): Promise<T> {
  try {
    return await (DESKTOP ? desktop() : dev());
  } catch (e) {
    throw new Error(message(e));
  }
}

export const engine = {
  status: () => call(() => invoke<ProxyStatus>('get_status'), () => http<ProxyStatus>('/api/status')),

  history: (query: string, method: string) =>
    call(
      () => invoke<TransactionSummary[]>('list_history', { query, method }),
      () => {
        const params = new URLSearchParams();
        if (query) params.append('q', query);
        if (method) params.append('method', method);
        return http<TransactionSummary[]>(`/api/history?${params.toString()}`);
      },
    ),

  transaction: (id: number) =>
    call(() => invoke<TransactionRecord>('get_transaction', { id }), () => http<TransactionRecord>(`/api/history/${id}`)),

  setRunning: (run: boolean) =>
    call(
      async () => {
        await invoke<ProxyStatus>(run ? 'start_proxy' : 'stop_proxy');
      },
      async () => {
        await http(`/api/proxy/${run ? 'start' : 'stop'}`, { method: 'POST' });
      },
    ),

  /** Desktop only: the dev daemon takes its port from DROPSUITE_PROXY_PORT. */
  listenerSettings: () =>
    call(
      () => invoke<ListenerSettings>('get_listener_settings'),
      () => Promise.reject(new Error('Listener settings are available in the desktop app.')),
    ),

  setListenerPort: (port: number) =>
    call(
      () => invoke<ListenerSettings>('set_listener_port', { port }),
      () => Promise.reject(new Error('Listener settings are available in the desktop app.')),
    ),

  /** Desktop only: HTTPS interception and root CA management. */
  httpsSettings: () =>
    call(
      () => invoke<HttpsSettings>('get_https_settings'),
      () => Promise.reject(new Error('HTTPS settings are available in the desktop app.')),
    ),

  setHttpsAllowlist: (allowlist: string[]) =>
    call(
      () => invoke<HttpsSettings>('set_https_allowlist', { allowlist }),
      () => Promise.reject(new Error('HTTPS settings are available in the desktop app.')),
    ),

  generateCaCertificate: () =>
    call(
      () => invoke<HttpsSettings>('generate_ca_certificate'),
      () => Promise.reject(new Error('CA generation is available in the desktop app.')),
    ),

  removeCaCertificate: () =>
    call(
      () => invoke<HttpsSettings>('remove_ca_certificate'),
      () => Promise.reject(new Error('CA removal is available in the desktop app.')),
    ),

  exportCaCertificate: () =>
    call(
      () => invoke<string>('export_ca_certificate'),
      () => Promise.reject(new Error('CA export is available in the desktop app.')),
    ),

  openChallengeBrowser: (url: string) =>
    call(
      () => invoke<void>('open_challenge_browser', { url }),
      () => Promise.reject(new Error('The challenge browser is available in the desktop app.')),
    ),

  importChallengeCookies: (host: string) =>
    call(
      () => invoke<ImportOutcome>('import_challenge_cookies', { host }),
      () => Promise.reject(new Error('The challenge browser is available in the desktop app.')),
    ),

  getApplySettings: () =>
    call(
      () => invoke<ApplySettings>('get_apply_settings'),
      () => Promise.reject(new Error('Header presets are available in the desktop app.')),
    ),

  setApplySettings: (preset: BrowserPreset, cookieJar: boolean) =>
    call(
      () => invoke<ApplySettings>('set_apply_settings', { preset, cookieJar }),
      () => Promise.reject(new Error('Header presets are available in the desktop app.')),
    ),

  listCookies: () =>
    call(
      () => invoke<CookieRow[]>('list_cookies'),
      () => Promise.reject(new Error('The cookie jar is available in the desktop app.')),
    ),

  listCookiesForHost: (host: string) =>
    call(
      () => invoke<CookieRow[]>('list_cookies_for_host', { host }),
      () => Promise.reject(new Error('The cookie jar is available in the desktop app.')),
    ),

  saveCookie: (host: string, raw: string) =>
    call(
      () => invoke<CookieRow>('save_cookie', { host, raw }),
      () => Promise.reject(new Error('The cookie jar is available in the desktop app.')),
    ),

  deleteCookie: (host: string, name: string, path: string) =>
    call(
      () => invoke<void>('delete_cookie', { host, name, path }),
      () => Promise.reject(new Error('The cookie jar is available in the desktop app.')),
    ),

  clearCookies: () =>
    call(
      () => invoke<void>('clear_cookies'),
      () => Promise.reject(new Error('The cookie jar is available in the desktop app.')),
    ),

  getInterceptStatus: () =>
    call(
      () => invoke<InterceptStatus>('get_intercept_status'),
      () => http<InterceptStatus>('/api/intercept/status'),
    ),

  setInterceptEnabled: (enabled: boolean) =>
    call(
      () => invoke<InterceptStatus>('set_intercept_enabled', { enabled }),
      () =>
        http<InterceptStatus>(`/api/intercept/enabled?enabled=${enabled}`, {
          method: 'POST',
        }),
    ),

  setInterceptRequests: (enabled: boolean) =>
    call(
      () => invoke<InterceptStatus>('set_intercept_requests', { enabled }),
      () => Promise.reject(new Error('Desktop only')),
    ),

  setInterceptResponses: (enabled: boolean) =>
    call(
      () => invoke<InterceptStatus>('set_intercept_responses', { enabled }),
      () => Promise.reject(new Error('Desktop only')),
    ),

  listInterceptedMessages: () =>
    call(
      () => invoke<InterceptedMessage[]>('list_intercepted_messages'),
      () => http<InterceptedMessage[]>('/api/intercept/messages'),
    ),

  forwardInterceptedMessage: (id: number, modifiedWire?: string) =>
    call(
      () => invoke<boolean>('forward_intercepted_message', { id, modifiedWire }),
      () =>
        http<boolean>(`/api/intercept/forward/${id}`, {
          method: 'POST',
        }),
    ),

  dropInterceptedMessage: (id: number) =>
    call(
      () => invoke<boolean>('drop_intercepted_message', { id }),
      () =>
        http<boolean>(`/api/intercept/drop/${id}`, {
          method: 'POST',
        }),
    ),

  forwardAllIntercepted: () =>
    call(
      () => invoke<void>('forward_all_intercepted'),
      () => Promise.reject(new Error('Desktop only')),
    ),

  dropAllIntercepted: () =>
    call(
      () => invoke<void>('drop_all_intercepted'),
      () => Promise.reject(new Error('Desktop only')),
    ),

  exportHar: (ids: number[]) =>
    call(
      () => invoke<string>('export_history_har', { ids }),
      () =>
        http<string>('/api/history/export/har', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(ids),
        }),
    ),

  openBrowser: (url?: string) =>
    call(
      () => invoke<void>('open_embedded_browser', { url }),
      () => Promise.reject(new Error('Embedded browser is available in the desktop app.')),
    ),

  clearHistory: () =>
    call(
      () => invoke<number>('clear_history'),
      () => http<{ removed: number }>('/api/history/clear', { method: 'POST' }).then((r) => r.removed),
    ),

  appInfo: () =>
    call(
      () => invoke<AppInfo>('get_app_info'),
      () => Promise.reject(new Error('Desktop only')),
    ),

  openAppFolder: (which: 'data' | 'logs') =>
    call(
      () => invoke<void>('open_app_folder', { which }),
      () => Promise.reject(new Error('Desktop only')),
    ),

  getStartAtLogin: () =>
    call(
      () => invoke<boolean>('get_start_at_login'),
      () => Promise.reject(new Error('Desktop only')),
    ),

  setStartAtLogin: (enabled: boolean) =>
    call(
      () => invoke<void>('set_start_at_login', { enabled }),
      () => Promise.reject(new Error('Desktop only')),
    ),

  checkForUpdate: () =>
    call(
      () => invoke<UpdateInfo>('check_for_update'),
      () => Promise.reject(new Error('Desktop only')),
    ),

  openReleasePage: () =>
    call(
      () => invoke<void>('open_release_page'),
      () => Promise.reject(new Error('Desktop only')),
    ),
};

/** Replay runs in the desktop engine only; there is no HTTP API for it. */
export const replay = {
  /** Rejects with a ReplayFailure. */
  send: async (request: { method: string; url: string; headers: [string, string][]; body: string }): Promise<ReplayResponse> => {
    if (!DESKTOP) throw { kind: 'unsupported', message: 'Replay is available in the DropSuite desktop app.' } satisfies ReplayFailure;
    try {
      return await invoke<ReplayResponse>('send_replay', { request });
    } catch (e) {
      if (e && typeof e === 'object' && 'kind' in e) throw e as ReplayFailure;
      throw { kind: 'internal', message: typeof e === 'string' ? e : 'The engine did not answer.' } satisfies ReplayFailure;
    }
  },
  cancel: () => (DESKTOP ? invoke<void>('cancel_replay') : Promise.resolve()),
};

export const repeater = {
  getTabs: () =>
    call(
      () => invoke<RepeaterTabRecord[]>('get_repeater_tabs'),
      () => http<RepeaterTabRecord[]>('/api/repeater/tabs'),
    ),
  saveTab: (tab: RepeaterTabRecord) =>
    call(
      () => invoke<number>('save_repeater_tab', { tab }),
      () =>
        http<{ id: number }>('/api/repeater/tabs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(tab),
        }).then((r) => r.id),
    ),
  deleteTab: (id: number) =>
    call(
      () => invoke<void>('delete_repeater_tab', { id }),
      () => http<void>(`/api/repeater/tabs/${id}`, { method: 'DELETE' }),
    ),
  listAttempts: (tabId: number, limit?: number) =>
    call(
      () => invoke<RepeaterAttemptRecord[]>('list_repeater_attempts', { tabId, limit }),
      () => http<RepeaterAttemptRecord[]>(`/api/repeater/attempts?tab_id=${tabId}`),
    ),
  saveAttempt: (attempt: RepeaterAttemptRecord) =>
    call(
      () => invoke<number>('save_repeater_attempt', { attempt }),
      () =>
        http<{ id: number }>('/api/repeater/attempts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(attempt),
        }).then((r) => r.id),
    ),
  clearAttempts: (tabId: number) =>
    call(
      () => invoke<void>('clear_repeater_attempts', { tabId }),
      () => http<void>(`/api/repeater/attempts?tab_id=${tabId}`, { method: 'DELETE' }),
    ),
};

export const scope = {
  getConfig: () =>
    call(
      () => invoke<ScopeConfig>('get_scope_config'),
      () => http<ScopeConfig>('/api/scope'),
    ),
  setConfig: (config: ScopeConfig) =>
    call(
      () => invoke<ScopeConfig>('set_scope_config', { config }),
      () =>
        http<ScopeConfig>('/api/scope', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(config),
        }),
    ),
};

export const matchReplace = {
  getConfig: () =>
    call(
      () => invoke<MatchReplaceConfig>('get_match_replace_config'),
      () => http<MatchReplaceConfig>('/api/match-replace'),
    ),
  setConfig: (config: MatchReplaceConfig) =>
    call(
      () => invoke<MatchReplaceConfig>('set_match_replace_config', { config }),
      () =>
        http<MatchReplaceConfig>('/api/match-replace', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(config),
        }),
    ),
};

export const sitemap = {
  getTree: () =>
    call(
      () => invoke<SiteNodeSummary[]>('get_sitemap'),
      () => http<SiteNodeSummary[]>('/api/sitemap'),
    ),
};

/** Intruder (Fuzzer) runs in the desktop engine only; results are polled, not pushed. */
export const intruder = {
  /** Validates and starts; resolves to the planned attempt count, or rejects with a message. */
  start: (
    request: { method: string; url: string; headers: [string, string][]; body: string },
    attack: IntruderAttack,
    maxConcurrency: number,
    delayMs: number,
    maxAttempts: number,
    encodeUrl: boolean,
  ): Promise<number> => {
    if (!DESKTOP) return Promise.reject(new Error('The Fuzzer is available in the DropSuite desktop app.'));
    return invoke<number>('start_intruder', { request, attack, maxConcurrency, delayMs, maxAttempts, encodeUrl }).catch((e) => {
      throw new Error(typeof e === 'string' ? e : e instanceof Error ? e.message : 'The engine did not answer.');
    });
  },
  status: (): Promise<IntruderStatus> =>
    DESKTOP ? invoke<IntruderStatus>('get_intruder_status') : Promise.reject(new Error('Desktop only')),
  results: (offset: number, limit: number): Promise<AttemptRow[]> =>
    DESKTOP ? invoke<AttemptRow[]>('list_intruder_results', { offset, limit }) : Promise.resolve([]),
  cancel: (): Promise<void> => (DESKTOP ? invoke<void>('cancel_intruder') : Promise.resolve()),
};

/** Drop AI (BYOK): the user's own model + key. Desktop only; the key never crosses this API. */
const aiErr = (e: unknown): never => {
  throw new Error(typeof e === 'string' ? e : e instanceof Error ? e.message : 'Drop AI did not respond.');
};
export const dropAi = {
  getConfig: (): Promise<DropAiStatus> =>
    DESKTOP ? invoke<DropAiStatus>('get_dropai_config').catch(aiErr) : Promise.reject(new Error('Drop AI is available in the desktop app.')),
  setConfig: (config: DropAiConfig): Promise<DropAiStatus> =>
    DESKTOP ? invoke<DropAiStatus>('set_dropai_config', { config }).catch(aiErr) : Promise.reject(new Error('Desktop only')),
  setKey: (key: string): Promise<boolean> =>
    DESKTOP ? invoke<boolean>('set_dropai_key', { key }).catch(aiErr) : Promise.reject(new Error('Desktop only')),
  clearKey: (): Promise<void> =>
    DESKTOP ? invoke<void>('clear_dropai_key').catch(aiErr) : Promise.resolve(),
  complete: (system: string, user: string): Promise<string> =>
    DESKTOP ? invoke<string>('dropai_complete', { system, user }).catch(aiErr) : Promise.reject(new Error('Desktop only')),
  test: (): Promise<string> =>
    DESKTOP ? invoke<string>('test_dropai').catch(aiErr) : Promise.reject(new Error('Desktop only')),
  listModels: (config: DropAiConfig): Promise<string[]> =>
    DESKTOP ? invoke<string[]>('list_dropai_models', { config }).catch(aiErr) : Promise.reject(new Error('Desktop only')),
};

