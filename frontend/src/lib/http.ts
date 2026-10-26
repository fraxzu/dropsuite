import { TransactionSummary } from '../types';

export type Header = [string, string];

export interface ParsedMessage {
  /** Request line or status line exactly as captured. */
  startLine: string;
  /** Raw bytes after the blank line that ends the head. */
  body: Uint8Array;
  /** True when the captured bytes contained a head/body separator. */
  hasHead: boolean;
}

const CRLFCRLF = [13, 10, 13, 10];

function indexOfSeq(bytes: Uint8Array, seq: number[], from = 0): number {
  outer: for (let i = from; i <= bytes.length - seq.length; i++) {
    for (let j = 0; j < seq.length; j++) {
      if (bytes[i + j] !== seq[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * The daemon stores each side as the full wire message (start line, headers, body).
 * Split it so the head can be rebuilt from the redacted header list and the
 * clear-text head bytes are never rendered.
 */
export function parseMessage(raw: number[] | undefined): ParsedMessage {
  const bytes = new Uint8Array(raw ?? []);
  const sep = indexOfSeq(bytes, CRLFCRLF);
  if (sep === -1) {
    return { startLine: '', body: bytes, hasHead: false };
  }
  const head = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, sep));
  const firstBreak = head.indexOf('\r\n');
  const startLine = firstBreak === -1 ? head : head.slice(0, firstBreak);
  return { startLine, body: bytes.subarray(sep + 4), hasHead: true };
}

export function headerValue(headers: Header[], name: string): string | undefined {
  const lower = name.toLowerCase();
  return headers.find(([k]) => k.toLowerCase() === lower)?.[1];
}

export function isRedacted(value: string): boolean {
  return /\[REDACTED[^\]]*\]/.test(value);
}

export function redactedHeaderNames(headers: Header[]): string[] {
  return headers.filter(([, v]) => isRedacted(v)).map(([k]) => k);
}

/** Wire-format head built from the (already redacted) parsed header list. */
export function buildRawHead(startLine: string, headers: Header[]): string {
  const lines = [startLine, ...headers.map(([k, v]) => `${k}: ${v}`)];
  return lines.join('\r\n');
}

/** Decode Transfer-Encoding: chunked. Returns null when the framing is malformed. */
export function dechunk(body: Uint8Array): Uint8Array | null {
  const out: number[] = [];
  let i = 0;
  const dec = new TextDecoder();
  while (i < body.length) {
    const lineEnd = indexOfSeq(body, [13, 10], i);
    if (lineEnd === -1) return null;
    const sizeStr = dec.decode(body.subarray(i, lineEnd)).split(';')[0].trim();
    const size = parseInt(sizeStr, 16);
    if (Number.isNaN(size)) return null;
    i = lineEnd + 2;
    if (size === 0) break;
    if (i + size > body.length) return null;
    for (let j = 0; j < size; j++) out.push(body[i + j]);
    i += size + 2;
  }
  return new Uint8Array(out);
}

export async function inflate(body: Uint8Array, encoding: string): Promise<Uint8Array | null> {
  const format = encoding === 'gzip' || encoding === 'x-gzip' ? 'gzip' : encoding === 'deflate' ? 'deflate' : null;
  if (!format || typeof DecompressionStream === 'undefined') return null;
  try {
    const stream = new Blob([body as BlobPart]).stream().pipeThrough(new DecompressionStream(format));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}

export interface DecodedBody {
  bytes: Uint8Array;
  /** Transformations applied for display, in order. Shown to the user. */
  transforms: string[];
  /** Encoding we could not undo (e.g. br). */
  undecoded?: string;
}

export async function decodeBody(body: Uint8Array, headers: Header[]): Promise<DecodedBody> {
  let bytes = body;
  const transforms: string[] = [];
  const te = headerValue(headers, 'transfer-encoding')?.toLowerCase() ?? '';
  if (te.includes('chunked')) {
    const d = dechunk(bytes);
    if (d) {
      bytes = d;
      transforms.push('de-chunked');
    }
  }
  const ce = headerValue(headers, 'content-encoding')?.toLowerCase().trim();
  if (ce && ce !== 'identity') {
    const inflated = await inflate(bytes, ce);
    if (inflated) {
      bytes = inflated;
      transforms.push(`${ce} decoded`);
    } else {
      return { bytes, transforms, undecoded: ce };
    }
  }
  return { bytes, transforms };
}

/** Heuristic: treat as binary when control bytes (other than whitespace) are common. */
export function looksBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 2048);
  if (n === 0) return false;
  let ctrl = 0;
  for (let i = 0; i < n; i++) {
    const b = bytes[i];
    if (b === 0) return true;
    if (b < 32 && b !== 9 && b !== 10 && b !== 13) ctrl++;
  }
  return ctrl / n > 0.05;
}

export function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

export type BodyKind = 'empty' | 'json' | 'image' | 'binary' | 'text';

export function classifyBody(bytes: Uint8Array, contentType: string | undefined): BodyKind {
  if (bytes.length === 0) return 'empty';
  const ct = (contentType ?? '').toLowerCase();
  if (/^image\/(png|jpe?g|gif|webp|bmp|avif|x-icon|vnd\.microsoft\.icon)/.test(ct)) return 'image';
  if (looksBinary(bytes)) return 'binary';
  if (ct.includes('json') || /^\s*[[{]/.test(bytesToText(bytes.subarray(0, 64)))) {
    try {
      JSON.parse(bytesToText(bytes));
      return 'json';
    } catch {
      /* falls through to text */
    }
  }
  return 'text';
}

/** `path` from the API is the absolute request target; show only path + query. */
export function displayPath(t: Pick<TransactionSummary, 'path'>): string {
  const p = t.path;
  if (p.startsWith('/')) return p;
  try {
    const u = new URL(p);
    return u.pathname + u.search;
  } catch {
    return p;
  }
}

export function splitPathQuery(path: string): { pathname: string; query: string } {
  const q = path.indexOf('?');
  return q === -1 ? { pathname: path, query: '' } : { pathname: path.slice(0, q), query: path.slice(q) };
}

export interface Param {
  source: 'query' | 'form';
  name: string;
  value: string;
}

export function extractParams(url: string, body: Uint8Array, headers: Header[]): Param[] {
  const params: Param[] = [];
  try {
    const u = new URL(url, 'http://placeholder.invalid');
    u.searchParams.forEach((value, name) => params.push({ source: 'query', name, value }));
  } catch {
    /* unparseable target: no query params */
  }
  const ct = headerValue(headers, 'content-type')?.toLowerCase() ?? '';
  if (ct.includes('application/x-www-form-urlencoded') && body.length) {
    new URLSearchParams(bytesToText(body)).forEach((value, name) => params.push({ source: 'form', name, value }));
  }
  return params;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} s`;
}

export function formatClock(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export function formatDateTime(ts: number): string {
  const d = new Date(ts);
  return `${d.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' })} ${formatClock(ts)}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}

/** Short MIME label for the grid: application/json; charset=utf-8 -> json */
export function shortType(ct: string | undefined): string {
  if (!ct) return '';
  const base = ct.split(';')[0].trim().toLowerCase();
  const sub = base.split('/')[1] ?? base;
  if (sub.includes('json')) return 'json';
  if (sub.includes('javascript') || sub === 'ecmascript') return 'script';
  if (sub.includes('xml')) return 'xml';
  if (sub === 'x-www-form-urlencoded') return 'form';
  if (base.startsWith('image/')) return sub.replace('svg+xml', 'svg');
  return sub;
}

export function statusClass(code: number): 's1' | 's2' | 's3' | 's4' | 's5' | 's0' {
  const c = Math.floor(code / 100);
  return c >= 1 && c <= 5 ? (`s${c}` as 's1' | 's2' | 's3' | 's4' | 's5') : 's0';
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Prefix the engine stores in place of a body it could not decode and inspect. */
export const OMITTED_PREFIX = '[DropSuite: body not stored]';

export interface OmittedBody {
  reason: string;
  contentType: string;
  length: number;
  /** Null when the engine recorded no hash (bodies under 64 bytes). */
  sha256: string | null;
}

/** Parse the fail-closed omission record, or null for an ordinary body. */
export function parseOmitted(body: Uint8Array): OmittedBody | null {
  if (body.length < OMITTED_PREFIX.length) return null;
  const text = bytesToText(body);
  if (!text.startsWith(OMITTED_PREFIX)) return null;
  const field = (key: string) => text.match(new RegExp(`${key}=([^;]*)`))?.[1]?.trim() ?? '';
  const length = parseInt(field('length'), 10);
  const sha = field('sha256');
  return {
    reason: field('reason'),
    contentType: field('content-type'),
    length: Number.isNaN(length) ? 0 : length,
    sha256: /^[0-9a-f]{64}$/.test(sha) ? sha : null,
  };
}

/** Plain-language explanation of an omission reason. */
export function describeOmission(reason: string): string {
  const enc = reason.match(/^content-encoding (.+) is not decoded$/);
  if (enc) return `It was compressed (${enc[1]}), and DropSuite does not decompress bodies yet.`;
  if (reason.startsWith('binary')) return 'It is binary or not UTF-8 text. Images and other media are included: they can carry data too.';
  if (reason.startsWith('multipart')) return 'Multipart bodies (file uploads and form parts) are not parsed yet.';
  if (reason.startsWith('malformed chunked')) return 'Its chunked transfer framing could not be decoded.';
  const limit = reason.match(/^body exceeds the (\d+) KB capture limit$/);
  if (limit) return `It is larger than the ${limit[1]} KB capture limit.`;
  if (isInterrupted(reason)) return 'The transfer stopped before the body was complete.';
  return reason;
}

/** True when the omitted body never arrived in full (as opposed to being withheld). */
export function isInterrupted(reason: string): boolean {
  return reason.startsWith('transfer interrupted');
}
