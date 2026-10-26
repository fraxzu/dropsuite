/**
 * Built-in content-discovery wordlist: common paths and files worth probing on a web target during
 * an AUTHORIZED assessment. Standard entries of the kind in dirb/SecLists common lists. These are
 * requested as-is (GET) to see which exist; nothing destructive.
 */
export const COMMON_PATHS: string[] = [
  // Admin / auth
  'admin', 'administrator', 'admin/login', 'login', 'logout', 'register', 'signup', 'signin',
  'dashboard', 'panel', 'cpanel', 'console', 'portal', 'user', 'users', 'account', 'accounts',
  'profile', 'me', 'auth', 'oauth', 'sso', 'wp-admin', 'wp-login.php',
  // Config / secrets (high value)
  '.env', '.env.local', '.env.backup', '.git/config', '.git/HEAD', '.gitignore', '.svn/entries',
  '.htaccess', '.htpasswd', 'web.config', 'config', 'config.php', 'config.json', 'config.yml',
  'settings.py', 'application.properties', 'docker-compose.yml', 'Dockerfile', '.aws/credentials',
  'id_rsa', 'private.key', 'secrets', 'secret', '.DS_Store', '.vscode', '.idea',
  // Backups / dumps
  'backup', 'backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql', 'dump.sql', 'database.sql',
  'site.zip', 'www.zip', 'old', 'bak', 'backup.bak',
  // API / docs
  'api', 'api/v1', 'api/v2', 'api/docs', 'swagger', 'swagger.json', 'swagger-ui', 'swagger-ui.html',
  'openapi.json', 'graphql', 'graphiql', 'v1', 'v2', 'rest',
  // Framework / monitoring
  'actuator', 'actuator/health', 'actuator/env', 'actuator/mappings', 'server-status', 'status',
  'health', 'healthz', 'metrics', 'debug', 'trace', 'phpinfo.php', 'info.php', 'test', 'test.php',
  // Data / files
  'robots.txt', 'sitemap.xml', '.well-known/security.txt', 'crossdomain.xml', 'uploads', 'upload',
  'files', 'file', 'images', 'img', 'assets', 'static', 'media', 'download', 'downloads',
  // Logs
  'logs', 'log', 'error.log', 'access.log', 'debug.log',
  // Tooling / deps
  'phpmyadmin', 'pma', 'adminer.php', 'composer.json', 'package.json', 'yarn.lock', 'composer.lock',
  'vendor', 'node_modules', 'cgi-bin',
  // Common app paths
  'setup', 'install', 'installer', 'readme.md', 'README.md', 'CHANGELOG.md', 'LICENSE',
  'internal', 'private', 'hidden', 'dev', 'staging', 'prod', 'beta', 'demo', 'sandbox',
  'settings', 'search', 'home', 'index.php', 'index.html', 'main', 'app',
];
