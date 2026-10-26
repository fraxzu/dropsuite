import { TransactionRecord } from '../types';
import { bytesToText, dechunk, headerValue, isRedacted, OmittedBody, parseMessage, parseOmitted } from './http';

/** Methods Replay sends in this milestone (mirrors the engine's list). */
export const REPLAY_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
/** Methods that usually change data on the server. */
export const STATE_CHANGING = ['POST', 'PUT', 'PATCH', 'DELETE'];

/**
 * The Replay editor's content. It lives in memory only: never in localStorage, settings,
 * history or logs, because it can hold real credentials the user typed in.
 */
export interface ReplayDraft {
  method: string;
  url: string;
  /** One `Name: value` per line. */
  headersText: string;
  body: string;
  /** Where the draft came from, when it was copied from history. */
  source?: {
    id: number;
    /** The original body was not stored; it cannot be recovered. */
    omittedBody: OmittedBody | null;
    /** Header fields left out of the copy, and why. */
    notCopied: string[];
  };
  /** The user chose to send without the original (unrecoverable) body. */
  bodyAcknowledged?: boolean;
}

export const NEW_DRAFT: ReplayDraft = {
  method: 'GET',
  url: 'http://',
  headersText: 'Accept: */*\nUser-Agent: DropSuite/0.1',
  body: '',
};

/** Header fields Replay sets itself or never sends, with the reason shown to the user. */
const NOT_COPIED: Record<string, string> = {
  host: 'Host (taken from the URL)',
  'content-length': 'Content-Length (set when sending)',
  'transfer-encoding': 'Transfer-Encoding (Replay sends Content-Length)',
  connection: 'Connection (one connection per send)',
  'proxy-connection': 'Proxy-Connection (proxy only)',
  'keep-alive': 'Keep-Alive (one connection per send)',
  te: 'TE (connection only)',
  upgrade: 'Upgrade (not supported in Replay)',
  'proxy-authorization': 'Proxy-Authorization (never sent to a target)',
};

/** Copy a captured, sanitized request into a draft. Redacted values stay visibly redacted. */
export function draftFromRecord(record: TransactionRecord): ReplayDraft {
  const msg = parseMessage(record.request_body);
  const omittedBody = parseOmitted(msg.body);
  let body = '';
  if (!omittedBody && msg.body.length) {
    const chunked = (headerValue(record.request_headers, 'transfer-encoding') ?? '').toLowerCase().includes('chunked');
    body = bytesToText(chunked ? dechunk(msg.body) ?? msg.body : msg.body);
  }
  const notCopied = new Set<string>();
  const kept = record.request_headers.filter(([name]) => {
    const why = NOT_COPIED[name.toLowerCase()];
    if (why) notCopied.add(why);
    return !why;
  });
  return {
    method: record.method.toUpperCase(),
    url: record.url,
    headersText: kept.map(([k, v]) => `${k}: ${v}`).join('\n'),
    body,
    source: { id: record.id, omittedBody, notCopied: [...notCopied] },
  };
}

export interface ParsedHeaders {
  headers: [string, string][];
  errors: string[];
}

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export function parseHeaderLines(text: string): ParsedHeaders {
  const headers: [string, string][] = [];
  const errors: string[] = [];
  text.split(/\r?\n/).forEach((line, i) => {
    if (!line.trim()) return;
    const colon = line.indexOf(':');
    const name = colon === -1 ? '' : line.slice(0, colon).trim();
    if (colon === -1 || !TOKEN.test(name)) {
      errors.push(`Header line ${i + 1} is not "Name: value".`);
      return;
    }
    headers.push([name, line.slice(colon + 1).trim()]);
  });
  return { headers, errors };
}

export interface Destination {
  host: string;
  port: number;
  label: string;
}

/** The host and port a draft would be sent to, or null when the URL has none. */
export function destinationOf(url: string): Destination | null {
  const m = /^(https?):\/\/([^/?#]*)/i.exec(url.trim());
  if (!m || !m[2] || m[2].includes('@')) return null;
  const isHttps = m[1].toLowerCase() === 'https';
  const authority = m[2];
  const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(authority);
  const host = v6 ? v6[1] : authority.split(':')[0];
  const portText = v6 ? v6[2] : authority.includes(':') ? authority.split(':')[1] : undefined;
  const port = portText ? Number(portText) : isHttps ? 443 : 80;
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port, label: v6 ? `[${host}]:${port}` : `${host}:${port}` };
}

export interface Issue {
  text: string;
  /** Offer "send without a body" for an unrecoverable historical body. */
  ackBody?: boolean;
}

/** Reasons the draft cannot be sent yet. The engine checks the same rules again. */
export function blockingIssues(draft: ReplayDraft, parsed: ParsedHeaders): Issue[] {
  const issues: Issue[] = [];
  const url = draft.url.trim();
  if (!REPLAY_METHODS.includes(draft.method)) issues.push({ text: `Choose one of ${REPLAY_METHODS.join(', ')}.` });
  if (!/^https?:\/\//i.test(url)) issues.push({ text: 'The URL must start with http:// or https://.' });
  else if (!destinationOf(url)) issues.push({ text: url.includes('@') ? 'Credentials in the URL are not sent. Use an Authorization header instead.' : 'The URL has no valid host and port.' });
  else if (/[\s\u0000-\u001f\u007f]/.test(url)) issues.push({ text: 'The URL contains spaces or control characters. Percent-encode them (a space is %20).' });
  if (isRedacted(url)) issues.push({ text: 'The URL still contains a [REDACTED] placeholder. Enter the real value or remove that parameter.' });
  issues.push(...parsed.errors.map((text) => ({ text })));
  for (const [name, value] of parsed.headers) {
    if (isRedacted(value)) issues.push({ text: `${name} still holds a [REDACTED] placeholder. History never keeps the real value: enter it or delete the header.` });
    if (name.toLowerCase() === 'transfer-encoding') issues.push({ text: 'Remove Transfer-Encoding. Replay sends bodies with Content-Length.' });
  }
  if (isRedacted(draft.body)) issues.push({ text: 'The body still contains a [REDACTED] placeholder. Enter the real value or remove it.' });
  if (draft.body.includes('[DropSuite: body not stored]')) issues.push({ text: "The body is DropSuite's summary of an unstored body, not the body itself. Write a new body or clear it." });
  const omitted = draft.source?.omittedBody;
  if (omitted && !draft.body && !draft.bodyAcknowledged) {
    issues.push({
      text: `The original ${omitted.length.toLocaleString()}-byte body was not stored and cannot be recovered. Write a new body, or send this request without one.`,
      ackBody: true,
    });
  }
  return issues;
}
