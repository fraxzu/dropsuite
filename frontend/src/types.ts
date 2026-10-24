export interface AppInfo {
  version: string;
  os: string;
  arch: string;
  data_dir: string;
  logs_dir: string;
}

export interface UpdateInfo {
  current: string;
  latest: string | null;
  newer: boolean;
  notes: string;
  url: string;
  checked: boolean;
  message: string;
}

export interface TransactionSummary {
  id: number;
  timestamp: number;
  duration_ms: number;
  method: string;
  host: string;
  path: string;
  status_code: number;
  content_type?: string;
  content_length: number;
}

export interface TransactionRecord {
  id: number;
  timestamp: number;
  duration_ms: number;
  method: string;
  url: string;
  host: string;
  path: string;
  request_headers: [string, string][];
  request_body: number[];
  status_code: number;
  response_headers: [string, string][];
  response_body: number[];
  content_type?: string;
  content_length: number;
}

/** What the Replay engine returns (desktop app only). Sanitized like history; never stored. */
export interface ReplayResponse {
  status: number;
  reason: string;
  headers: [string, string][];
  /** Status line, headers and body (or an omission record). */
  message: number[];
  content_type?: string | null;
  total_bytes: number;
  sent_bytes: number;
  duration_ms: number;
  destination: string;
  dropped_headers: string[];
  /** The request as sent, sanitized like history (body capped at 16 KB). */
  request_target: string;
  request_headers: [string, string][];
  request_message: number[];
  /** Present when the answer was a bot challenge rather than the application's own response. */
  challenge: ChallengeSignal | null;
  /** Jar cookies attached to the request that produced this response. */
  cookies_attached: number;
}

/** Bot-challenge detection result. */
export interface ChallengeSignal {
  vendor: 'cloudflare' | 'akamai' | 'data_dome' | 'imperva' | 'sucuri';
  kind: 'js' | 'interactive' | 'blocked' | 'rate_limited';
  /** The marker that produced the detection, shown as evidence. */
  evidence: string;
}

export type BrowserPreset = 'off' | 'chrome' | 'edge' | 'firefox' | 'safari';

export interface ApplySettings {
  preset: BrowserPreset;
  cookie_jar: boolean;
}

/** What an import collected; names, and whether the clearance cookie was among them. */
export interface ImportOutcome {
  imported: string[];
  has_clearance: boolean;
  /** Whether the window's User-Agent was recorded and will be reused automatically. */
  pinned: boolean;
}

export type ActiveCheck =
  | 'reflected_xss'
  | 'sql_error'
  | 'sql_boolean'
  | 'sql_time'
  | 'path_traversal'
  | 'open_redirect'
  | 'open_redirect_xss'
  | 'cors_misconfig'
  | 'crlf_injection'
  | 'host_header_injection'
  | 'method_override';
export type ActiveConfidence = 'info' | 'low' | 'medium' | 'high';

export interface ActiveFinding {
  kind: ActiveCheck;
  confidence: ActiveConfidence;
  point: string;
  payload: string;
  evidence: string;
  status: number;
}

export interface ActiveScanReport {
  findings: ActiveFinding[];
  requests: number;
  points: number;
  stopped: 'blocked' | 'budget' | 'rate_limited' | null;
  skipped_non_html: boolean;
  skipped_waf: boolean;
  blocked_by_waf: boolean;
  skipped_infrastructure: boolean;
  waf_vendor: string | null;
}

export interface CookieRow {
  host: string;
  name: string;
  value: string;
  path: string;
  domain: string | null;
  secure: boolean;
  http_only: boolean;
  expires_at: number | null;
}

export interface ReplayFailure {
  /** invalid, unsupported, loop, resolve, refused, connect, timeout, malformed, interrupted, cancelled, busy */
  kind: string;
  message: string;
}

/** Listener configuration, desktop app only. */
export interface ListenerSettings {
  bind_address: string;
  port: number;
  default_port: number;
  min_port: number;
  max_port: number;
  /** A test run pinned the port with DROPSUITE_PROXY_PORT; the saved choice is not used. */
  port_from_env: boolean;
  log_dir: string | null;
}

export interface ProxyStatus {
  is_running: boolean;
  bind_address: string;
  port: number;
  total_captured: number;
  total_bytes_transferred: number;
}

/** HTTPS interception and local CA settings (desktop app only). */
export interface HttpsSettings {
  ca_present: boolean;
  fingerprint: string | null;
  not_before_unix: number | null;
  not_after_unix: number | null;
  key_protection: string;
  cert_pem: string | null;
  allowlist: string[];
}

/** Intercept engine state. */
export interface InterceptStatus {
  enabled: boolean;
  intercept_requests: boolean;
  intercept_responses: boolean;
  queue_len: number;
}

/** An in-flight HTTP message held for user decision. */
export interface InterceptedMessage {
  id: number;
  kind: 'request' | 'response';
  method: string;
  url: string;
  status_code: number | null;
  host: string;
  path: string;
  headers: [string, string][];
  raw_message: string;
  body_len: number;
  timestamp_ms: number;
}

export interface RepeaterTabRecord {
  id: number;
  name: string;
  color?: string | null;
  group_name?: string | null;
  method: string;
  url: string;
  headers: [string, string][];
  body: string;
  created_at: number;
  updated_at: number;
}

export interface RepeaterAttemptRecord {
  id: number;
  tab_id: number;
  seq: number;
  created_at: number;
  method: string;
  destination: string;
  status_code?: number | null;
  duration_ms: number;
  total_bytes: number;
  sent_bytes: number;
  response_headers: [string, string][];
  response_body: number[];
  content_type?: string | null;
  failure_kind?: string | null;
  failure_message?: string | null;
}

export type ScopeRuleType = 'include' | 'exclude';

export interface ScopeRule {
  id: string;
  enabled: boolean;
  rule_type: ScopeRuleType;
  protocol?: string | null;
  host: string;
  port?: number | null;
  path_prefix?: string | null;
}

export interface ScopeConfig {
  enabled: boolean;
  drop_out_of_scope: boolean;
  rules: ScopeRule[];
}

export type MatchReplaceTarget =
  | 'request_header'
  | 'request_body'
  | 'response_header'
  | 'response_body'
  | 'request_first_line';

export interface MatchReplaceRule {
  id: string;
  enabled: boolean;
  comment: string;
  target: MatchReplaceTarget;
  is_regex: boolean;
  pattern: string;
  replacement: string;
}

export interface MatchReplaceConfig {
  enabled: boolean;
  rules: MatchReplaceRule[];
}

/** Drop AI (BYOK) - mirrors dropsuite-app::dropai. The key is never carried in these types. */
export type DropAiProvider = 'openai-compatible' | 'anthropic-compatible';

export interface DropAiConfig {
  provider: DropAiProvider;
  base_url: string;
  model: string;
  temperature: number;
  max_tokens: number;
}

export interface DropAiStatus extends DropAiConfig {
  has_key: boolean;
  key_protection: string;
}

/** Intruder (Fuzzer) - mirrors the serde tags in dropsuite-core::intruder. */
export type PayloadSet =
  | { kind: 'list'; values: string[] }
  | { kind: 'number_range'; from: number; to: number; step: number };

export type IntruderAttack =
  | { type: 'sniper'; payloads: PayloadSet }
  | { type: 'cluster_bomb'; payload_sets: PayloadSet[] };

export interface IntruderStatus {
  running: boolean;
  done: boolean;
  planned: number;
  completed: number;
  scope_skipped: number;
  error: string | null;
}

/** One finished attempt. Response bodies are never kept. */
export interface AttemptRow {
  index: number;
  replacements: string[];
  ok: boolean;
  status: number | null;
  total_bytes: number | null;
  duration_ms: number | null;
  destination: string | null;
  error_kind: string | null;
  error_message: string | null;
  challenge: ChallengeSignal | null;
}

export interface SiteNodeSummary {
  key: string;
  host: string;
  path: string;
  name: string;
  depth: number;
  in_scope: boolean;
  total: number;
  status_classes: string[];
  methods: string[];
  parameters: string[];
  children: SiteNodeSummary[];
}
