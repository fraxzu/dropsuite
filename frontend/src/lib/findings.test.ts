import { describe, expect, it } from 'vitest';
import { analyzeResponse, isInfrastructure, looksLikeChallenge } from './findings';

const html = { 'content-type': 'text/html; charset=utf-8' } as const;

function input(url: string, headers: Record<string, string>, body = '<html><body>x</body></html>') {
  return {
    url,
    status: 200,
    headers: Object.entries(headers) as [string, string][],
    body,
    paramValues: [] as string[],
  };
}

const titles = (url: string, headers: Record<string, string>, body?: string) =>
  analyzeResponse(input(url, headers, body)).map((f) => f.title);

describe('page-level gating', () => {
  it('does not report header rules for a JavaScript asset', () => {
    const found = titles('https://a.test/app.js', { 'content-type': 'application/javascript' }, 'var x=1;');
    expect(found).toEqual([]);
  });

  it('reports missing CSP for an HTML document', () => {
    expect(titles('https://a.test/', html)).toContain('Missing Content-Security-Policy');
  });

  it('does not report a document that has CSP', () => {
    expect(titles('https://a.test/', { ...html, 'content-security-policy': "default-src 'self'" })).not.toContain(
      'Missing Content-Security-Policy',
    );
  });

  it('skips a challenge page from the provider', () => {
    const found = titles('https://a.test/', { ...html, 'cf-mitigated': 'challenge' }, '<title>Just a moment...</title>');
    expect(found).not.toContain('Missing Content-Security-Policy');
    expect(found).not.toContain('Missing HSTS');
  });

  it('skips provider paths', () => {
    expect(isInfrastructure('https://a.test/cdn-cgi/challenge-platform/h/b/x')).toBe(true);
    expect(isInfrastructure('https://a.test/TSPD/abc?type=11')).toBe(true);
    expect(isInfrastructure('https://a.test/blog/post')).toBe(false);
    expect(titles('https://a.test/cdn-cgi/rum?', html)).not.toContain('Missing Content-Security-Policy');
  });

  it('detects a challenge by body marker even without a header', () => {
    expect(looksLikeChallenge([], '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script>')).toBe(true);
  });
});

describe('cookie findings', () => {
  it('reports one finding per cookie listing every missing flag', () => {
    const found = analyzeResponse(
      input('https://a.test/', { ...html, 'set-cookie': 'sid=1; Path=/' }),
    ).filter((f) => f.title.startsWith('Weak cookie flags'));
    expect(found).toHaveLength(1);
    expect(found[0].detail).toContain('Secure');
    expect(found[0].detail).toContain('HttpOnly');
    expect(found[0].detail).toContain('SameSite');
    expect(found[0].severity).toBe('medium');
  });

  it('stays quiet when the cookie is fully flagged', () => {
    const found = titles('https://a.test/', {
      ...html,
      'set-cookie': 'sid=1; Secure; HttpOnly; SameSite=Lax',
    });
    expect(found.filter((t) => t.startsWith('Weak cookie flags'))).toEqual([]);
  });

  it('does not complain about Secure on a plain HTTP page', () => {
    const found = analyzeResponse(
      input('http://a.test/', { ...html, 'set-cookie': 'sid=1; HttpOnly; SameSite=Lax' }),
    ).filter((f) => f.title.startsWith('Weak cookie flags'));
    expect(found).toHaveLength(0);
  });

  it('separates two cookies into two findings', () => {
    const headers = { ...html } as Record<string, string>;
    const pairs: [string, string][] = [
      ['content-type', 'text/html'],
      ['set-cookie', 'a=1'],
      ['set-cookie', 'b=2'],
    ];
    const found = analyzeResponse({
      url: 'https://a.test/',
      status: 200,
      headers: pairs,
      body: '<html></html>',
      paramValues: [],
    });
    expect(found.filter((f) => f.title.startsWith('Weak cookie flags'))).toHaveLength(2);
    expect(headers['content-type']).toContain('text/html');
  });
});

describe('server errors', () => {
  it('reports a 5xx from the application', () => {
    const found = analyzeResponse({ ...input('https://a.test/', html), status: 502 });
    expect(found.map((f) => f.title)).toContain('Server error (502)');
  });

  it('ignores a 5xx on a challenge page', () => {
    const found = analyzeResponse({
      ...input('https://a.test/', { ...html, 'cf-mitigated': 'challenge' }),
      status: 520,
    });
    expect(found.map((f) => f.title)).not.toContain('Server error (520)');
  });
});

describe('infrastructure flag', () => {
  it('marks findings from provider paths as not about the target', () => {
    const found = analyzeResponse(
      input('https://a.test/cdn-cgi/rum?', { 'content-type': 'text/html' }, 'near "x": SQL syntax error'),
    );
    expect(found.map((f) => f.title)).toContain('Possible SQL error leaked');
    expect(found.every((f) => f.aboutTarget === false)).toBe(true);
  });
});
