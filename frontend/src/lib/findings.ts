/**
 * Passive response analysis for the Replay viewer and the scanner. These are read-only checks on
 * a response that was already fetched: missing or weak security headers, information disclosure,
 * insecure cookies, reflected input, risky CORS, and error/stack-trace leakage. Nothing is sent.
 *
 * Two gates keep the output close to the application rather than to whatever edge infrastructure
 * happened to be in the capture:
 *
 * - **Documents only.** A header-hardening rule (CSP, HSTS, clickjacking, cookie flags) is about a
 *   page a browser renders. A `.js`, image or JSON API missing `X-Frame-Options` is not a finding.
 * - **Not the challenge provider.** `/cdn-cgi/`, `/TSPD/` and challenge pages belong to Cloudflare,
 *   not to the site under test; reporting "missing CSP" against them buries the real result.
 */
export type Severity = 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  severity: Severity;
  title: string;
  detail: string;
  /** False for edge/challenge infrastructure; the UI can label or hide those. */
  aboutTarget?: boolean;
}

const RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };

interface Input {
  url: string;
  status: number;
  headers: [string, string][];
  body: string;
  /** Values of the request's query/body parameters, for reflection checks. */
  paramValues: string[];
}

const get = (headers: [string, string][], name: string): string | undefined =>
  headers.find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];

const getAll = (headers: [string, string][], name: string): string[] =>
  headers.filter(([k]) => k.toLowerCase() === name.toLowerCase()).map(([, v]) => v);

/** Paths served by Cloudflare itself rather than by the application. */
export function isInfrastructure(url: string): boolean {
  return /\/(cdn-cgi|TSPD|__cf)\//i.test(url) || /\/cdn-cgi(\/|$)/i.test(url);
}

/** A response that is the challenge provider's page, not the site's own answer. */
export function looksLikeChallenge(headers: [string, string][], body: string): boolean {
  if (get(headers, 'cf-mitigated')) return true;
  const head = body.slice(0, 8000).toLowerCase();
  return head.includes('/cdn-cgi/challenge-platform') || head.includes('just a moment');
}

/** Only a rendered document carries page-level header expectations. */
function isDocument(headers: [string, string][]): boolean {
  const ct = (get(headers, 'content-type') ?? '').toLowerCase();
  return ct.includes('text/html') || ct.includes('application/xhtml') || ct.includes('text/xml');
}

export function analyzeResponse(input: Input): Finding[] {
  const { url, status, headers, body } = input;
  const out: Finding[] = [];
  const https = url.toLowerCase().startsWith('https://');

  const infrastructure = isInfrastructure(url);
  const challenge = looksLikeChallenge(headers, body);
  const document = isDocument(headers);
  // Page-level expectations only make sense for the application's own documents.
  const pageLevel = document && !challenge && !infrastructure;
  const aboutTarget = !infrastructure && !challenge;

  // --- Security headers ---------------------------------------------------------------------
  if (pageLevel) {
    const csp = get(headers, 'content-security-policy');
    if (!csp) {
      out.push({ severity: 'medium', title: 'Missing Content-Security-Policy', detail: 'No CSP header. A policy limits where scripts/resources can load from and is a key XSS mitigation.', aboutTarget });
    } else if (!/default-src|script-src/i.test(csp)) {
      out.push({ severity: 'low', title: 'Weak Content-Security-Policy', detail: `CSP has no default-src or script-src, so it does little against XSS: "${csp.slice(0, 80)}".`, aboutTarget });
    }
    if (!get(headers, 'x-content-type-options')) {
      out.push({ severity: 'low', title: 'Missing X-Content-Type-Options', detail: 'Without "nosniff", browsers may MIME-sniff responses, enabling some content-type attacks.', aboutTarget });
    }
    if (!get(headers, 'x-frame-options') && !/frame-ancestors/i.test(csp ?? '')) {
      out.push({ severity: 'medium', title: 'No clickjacking protection', detail: 'No X-Frame-Options and no CSP frame-ancestors: the page can be framed (clickjacking).', aboutTarget });
    }
    if (https && !get(headers, 'strict-transport-security')) {
      out.push({ severity: 'medium', title: 'Missing HSTS', detail: 'HTTPS response without Strict-Transport-Security: downgrade/SSL-strip attacks are not prevented.', aboutTarget });
    }
    if (!get(headers, 'referrer-policy')) {
      out.push({ severity: 'info', title: 'No Referrer-Policy', detail: 'The Referer header may leak URLs (with tokens) to other sites.', aboutTarget });
    }
  }

  // --- Information disclosure ---------------------------------------------------------------
  if (aboutTarget) {
    const server = get(headers, 'server');
    if (server && /\d/.test(server)) {
      out.push({ severity: 'low', title: 'Server version disclosed', detail: `Server header reveals software and version: "${server}". Helps an attacker match known CVEs.`, aboutTarget });
    }
    for (const h of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
      const v = get(headers, h);
      if (v) out.push({ severity: 'low', title: `Technology disclosed (${h})`, detail: `"${h}: ${v}" reveals the backend technology.`, aboutTarget });
    }
  }

  // --- Cookies ------------------------------------------------------------------------------
  // One finding per cookie, carrying every missing flag, instead of three findings per cookie.
  if (pageLevel) {
    for (const c of getAll(headers, 'set-cookie')) {
      const name = c.split('=')[0]?.trim() ?? 'cookie';
      const flags = c.toLowerCase();
      const missing: string[] = [];
      let severity: Severity = 'low';
      if (https && !/\bsecure\b/.test(flags)) {
        missing.push('Secure (could travel over plain HTTP)');
        severity = 'medium';
      }
      if (!/\bhttponly\b/.test(flags)) {
        missing.push('HttpOnly (readable from JavaScript, so stealable via XSS)');
        severity = 'medium';
      }
      if (!/\bsamesite\b/.test(flags)) missing.push('SameSite (weaker CSRF protection)');
      if (missing.length) {
        out.push({ severity, title: `Weak cookie flags (${name})`, detail: `Cookie "${name}" lacks: ${missing.join('; ')}.`, aboutTarget });
      }
    }
  }

  // --- CORS ---------------------------------------------------------------------------------
  const acao = get(headers, 'access-control-allow-origin');
  if (acao === '*') {
    const creds = (get(headers, 'access-control-allow-credentials') ?? '').toLowerCase() === 'true';
    out.push({
      severity: creds ? 'high' : 'low',
      title: 'Permissive CORS',
      detail: creds ? 'Access-Control-Allow-Origin: * with credentials allowed exposes authenticated data to any origin.' : 'Access-Control-Allow-Origin: * lets any site read this response.',
      aboutTarget,
    });
  }

  // --- Reflected input (possible XSS) -------------------------------------------------------
  if (document) {
    for (const v of input.paramValues) {
      if (v.length < 3) continue;
      if (body.includes(v)) {
        const marker = /[<>"'`]/.test(v);
        out.push({
          severity: marker ? 'high' : 'medium',
          title: marker ? 'Input reflected unencoded (possible XSS)' : 'Input reflected in response',
          detail: `The value "${v.slice(0, 60)}" appears verbatim in the response body${marker ? ', including special characters that were not encoded' : ''}.`,
          aboutTarget,
        });
        break; // one reflection finding is enough signal
      }
    }
  }

  // --- Body signals -------------------------------------------------------------------------
  const low = body.slice(0, 20000).toLowerCase();
  if (/(sql syntax|mysql_fetch|ora-\d{5}|unclosed quotation mark|psql:|sqlstate|you have an error in your sql)/i.test(low)) {
    out.push({ severity: 'high', title: 'Possible SQL error leaked', detail: 'The response contains database error text, a strong signal of SQL injection.', aboutTarget });
  }
  if (/(traceback \(most recent call last\)|exception in thread|stack trace:|at [\w.$]+\([\w.]+\.java:\d+\)|\.php on line \d+)/i.test(low)) {
    out.push({ severity: 'medium', title: 'Stack trace / error disclosed', detail: 'The response leaks a stack trace or server error, revealing internal paths and logic.', aboutTarget });
  }
  if (/<title>index of \//i.test(low) || /\[to parent directory\]/i.test(low)) {
    out.push({ severity: 'medium', title: 'Directory listing', detail: 'The server returned a directory listing, exposing files that should not be browsable.', aboutTarget });
  }
  // A 5xx from the challenge provider says nothing about the site's own error handling.
  if (status >= 500 && !challenge && !infrastructure) {
    out.push({ severity: 'info', title: `Server error (${status})`, detail: 'A 5xx status can indicate an unhandled condition worth probing.', aboutTarget });
  }

  out.sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  return out;
}

export function topSeverity(findings: Finding[]): Severity | null {
  return findings.length ? findings.reduce((s, f) => (RANK[f.severity] < RANK[s] ? f.severity : s), 'info' as Severity) : null;
}
