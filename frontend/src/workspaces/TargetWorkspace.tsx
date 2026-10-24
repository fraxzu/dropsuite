import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  ChevronRight,
  Globe,
  Info,
  Plus,
  Shield,
  Sliders,
  Trash2,
} from 'lucide-react';
import {
  MatchReplaceConfig,
  MatchReplaceRule,
  MatchReplaceTarget,
  ProxyStatus,
  ScopeConfig,
  ScopeRule,
  ScopeRuleType,
  TransactionRecord,
  TransactionSummary,
} from '../types';
import { useHistory, useTransaction } from '../lib/api';
import { engine, matchReplace, scope } from '../lib/transport';
import { useStoredState } from '../lib/useStoredState';
import { HistoryGrid, SortState, sortRows } from '../components/HistoryGrid';
import { Inspector } from '../components/Inspector';
import { buildSiteTree, inNode, SiteMap, SiteNode } from '../components/SiteMap';
import { Splitter } from '../components/Splitter';
import { isEditable } from './ProxyWorkspace';

interface TargetWorkspaceProps {
  active: boolean;
  status: ProxyStatus | null;
  connected: boolean | null;
  onToast: (msg: string) => void;
  onSendToReplay: (record: TransactionRecord) => void;
}

const MIN_TREE = 200;
const MIN_GRID = 100;
const MIN_INSPECTOR = 180;

type TargetSubtab = 'sitemap' | 'scope' | 'match_replace';

export const TargetWorkspace: React.FC<TargetWorkspaceProps> = ({
  active,
  status,
  connected,
  onToast,
  onSendToReplay,
}) => {
  const [subtab, setSubtab] = useStoredState<TargetSubtab>('target.subtab', 'sitemap');

  // ================= SITE MAP STATE =================
  const { items, refresh } = useHistory({ q: '', method: '' }, active);
  const all = items ?? [];
  const roots = useMemo(() => buildSiteTree(all), [all]);

  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  // The site map is built from HTTP history, so clearing it clears the shared history
  // (this also empties the Proxy history and the Scanner). Nothing is sent.
  const clearSitemap = async () => {
    const n = all.length;
    if (n === 0) return;
    if (!window.confirm(`Delete all ${n} captured request(s)? This clears the site map, the Proxy history and the Scanner. This cannot be undone.`)) {
      return;
    }
    try {
      const removed = await engine.clearHistory();
      setSelectedKey(null);
      setSelectedId(null);
      await refresh();
      onToast(`Cleared ${removed} request(s)`);
    } catch (err) {
      onToast(`Clear failed: ${err}`);
    }
  };
  const [expandedList, setExpandedList] = useStoredState<string[]>('target.expanded', []);
  const expanded = useMemo(() => new Set(expandedList), [expandedList]);
  const [treeW, setTreeW] = useStoredState<number>('target.treeWidth', 300);
  const [inspectorRatio, setInspectorRatio] = useStoredState<number>('target.inspector', 0.5);
  const [sort, setSort] = useStoredState<SortState>('target.sort', { key: 'id', dir: 'desc' });
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [onlyInScope, setOnlyInScope] = useStoredState<boolean>('target.onlyInScope', false);
  const detail = useTransaction(selectedId);

  const gridRef = useRef<HTMLDivElement>(null);
  const hostRef = useRef<HTMLDivElement>(null);
  const splitRef = useRef<HTMLDivElement>(null);
  const [hostW, setHostW] = useState(1200);
  const [splitH, setSplitH] = useState(600);

  // ================= SCOPE STATE =================
  const [scopeCfg, setScopeCfg] = useState<ScopeConfig>({
    enabled: false,
    drop_out_of_scope: false,
    rules: [],
  });
  const [newRuleType, setNewRuleType] = useState<ScopeRuleType>('include');
  const [newRuleProto, setNewRuleProto] = useState<string>('any');
  const [newRuleHost, setNewRuleHost] = useState<string>('');
  const [newRulePort, setNewRulePort] = useState<string>('');
  const [newRulePath, setNewRulePath] = useState<string>('');

  // ================= MATCH & REPLACE STATE =================
  const [mrCfg, setMrCfg] = useState<MatchReplaceConfig>({
    enabled: false,
    rules: [],
  });
  const [newMrTarget, setNewMrTarget] = useState<MatchReplaceTarget>('request_header');
  const [newMrRegex, setNewMrRegex] = useState<boolean>(false);
  const [newMrPattern, setNewMrPattern] = useState<string>('');
  const [newMrReplacement, setNewMrReplacement] = useState<string>('');
  const [newMrComment, setNewMrComment] = useState<string>('');

  useLayoutEffect(() => {
    const a = hostRef.current;
    const b = splitRef.current;
    if (!a || !b) return;
    const ro = new ResizeObserver(() => {
      setHostW(a.clientWidth);
      setSplitH(b.clientHeight);
    });
    ro.observe(a);
    ro.observe(b);
    return () => ro.disconnect();
  }, []);

  // Fetch Scope and Match & Replace configs on active
  useEffect(() => {
    if (!active) return;
    scope.getConfig().then(setScopeCfg).catch(() => {});
    matchReplace.getConfig().then(setMrCfg).catch(() => {});
  }, [active]);

  // Select first host once traffic exists
  useEffect(() => {
    if (selectedKey === null && roots.length) {
      setSelectedKey(roots[0].key);
      if (!expandedList.length) setExpandedList(roots.map((r) => r.key));
    }
  }, [roots, selectedKey, expandedList.length, setExpandedList]);

  const node = useMemo(() => {
    const find = (nodes: SiteNode[]): SiteNode | null => {
      for (const n of nodes) {
        if (n.key === selectedKey) return n;
        const c = find(n.children);
        if (c) return c;
      }
      return null;
    };
    return find(roots);
  }, [roots, selectedKey]);

  // Scope matching helper on frontend for SiteMap filter
  const isHostInScope = (host: string): boolean => {
    if (!scopeCfg.enabled || scopeCfg.rules.length === 0) return true;
    const enabledRules = scopeCfg.rules.filter((r) => r.enabled);
    if (enabledRules.length === 0) return true;

    // Check excludes
    for (const r of enabledRules.filter((r) => r.rule_type === 'exclude')) {
      if (r.host === '*' || host === r.host || (r.host.startsWith('*.') && host.endsWith(r.host.slice(1)))) {
        return false;
      }
    }

    const includes = enabledRules.filter((r) => r.rule_type === 'include');
    if (includes.length === 0) return true;

    for (const r of includes) {
      if (r.host === '*' || host === r.host || (r.host.startsWith('*.') && host.endsWith(r.host.slice(1)))) {
        return true;
      }
    }
    return false;
  };

  const filteredItems = useMemo(() => {
    let list = node ? all.filter((t) => inNode(t, node)) : [];
    if (onlyInScope && scopeCfg.enabled) {
      list = list.filter((t) => isHostInScope(t.host));
    }
    return list;
  }, [all, node, onlyInScope, scopeCfg]);

  const rows = useMemo(() => sortRows(filteredItems, sort), [filteredItems, sort]);
  const summary: TransactionSummary | null = useMemo(
    () => all.find((t) => t.id === selectedId) ?? null,
    [all, selectedId]
  );

  const move = (to: number | 'start' | 'end') => {
    if (!rows.length) return;
    const i = to === 'start' ? 0 : to === 'end' ? rows.length - 1 : Math.min(rows.length - 1, Math.max(0, to));
    setSelectedId(rows[i].id);
  };

  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || isEditable(e.target)) return;
      if (e.key === 'Escape' && selectedId !== null) setSelectedId(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  // Scope handlers
  const saveScope = async (updated: ScopeConfig) => {
    setScopeCfg(updated);
    try {
      await scope.setConfig(updated);
      onToast('Target scope updated');
    } catch (e) {
      onToast(`Failed to update scope: ${e}`);
    }
  };

  const addScopeRule = (e: React.FormEvent) => {
    e.preventDefault();
    const h = newRuleHost.trim();
    if (!h) {
      onToast('Please specify a host pattern');
      return;
    }
    const rule: ScopeRule = {
      id: `rule_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      enabled: true,
      rule_type: newRuleType,
      protocol: newRuleProto === 'any' ? null : newRuleProto,
      host: h,
      port: newRulePort.trim() ? parseInt(newRulePort.trim(), 10) : null,
      path_prefix: newRulePath.trim() ? (newRulePath.trim().startsWith('/') ? newRulePath.trim() : `/${newRulePath.trim()}`) : null,
    };
    const updated: ScopeConfig = {
      ...scopeCfg,
      rules: [...scopeCfg.rules, rule],
    };
    saveScope(updated);
    setNewRuleHost('');
    setNewRulePort('');
    setNewRulePath('');
  };

  const toggleScopeRule = (id: string) => {
    const updated: ScopeConfig = {
      ...scopeCfg,
      rules: scopeCfg.rules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
    };
    saveScope(updated);
  };

  const deleteScopeRule = (id: string) => {
    const updated: ScopeConfig = {
      ...scopeCfg,
      rules: scopeCfg.rules.filter((r) => r.id !== id),
    };
    saveScope(updated);
  };

  // Match & Replace handlers
  const saveMatchReplace = async (updated: MatchReplaceConfig) => {
    setMrCfg(updated);
    try {
      await matchReplace.setConfig(updated);
      onToast('Match & Replace config updated');
    } catch (e) {
      onToast(`Failed to update Match & Replace: ${e}`);
    }
  };

  const addMatchReplaceRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMrPattern && !newMrReplacement) {
      onToast('Specify at least a match pattern or a replacement');
      return;
    }
    const rule: MatchReplaceRule = {
      id: `mr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      enabled: true,
      comment: newMrComment.trim() || 'Custom rule',
      target: newMrTarget,
      is_regex: newMrRegex,
      pattern: newMrPattern,
      replacement: newMrReplacement,
    };
    const updated: MatchReplaceConfig = {
      ...mrCfg,
      rules: [...mrCfg.rules, rule],
    };
    saveMatchReplace(updated);
    setNewMrPattern('');
    setNewMrReplacement('');
    setNewMrComment('');
  };

  const toggleMatchReplaceRule = (id: string) => {
    const updated: MatchReplaceConfig = {
      ...mrCfg,
      rules: mrCfg.rules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
    };
    saveMatchReplace(updated);
  };

  const deleteMatchReplaceRule = (id: string) => {
    const updated: MatchReplaceConfig = {
      ...mrCfg,
      rules: mrCfg.rules.filter((r) => r.id !== id),
    };
    saveMatchReplace(updated);
  };

  const applyTemplate = (tmpl: {
    comment: string;
    target: MatchReplaceTarget;
    is_regex: boolean;
    pattern: string;
    replacement: string;
  }) => {
    const rule: MatchReplaceRule = {
      id: `mr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      enabled: true,
      ...tmpl,
    };
    const updated: MatchReplaceConfig = {
      ...mrCfg,
      enabled: true,
      rules: [...mrCfg.rules, rule],
    };
    saveMatchReplace(updated);
  };

  const total = status?.total_captured ?? 0;
  const truncated = total > all.length && all.length > 0;
  const treePx = Math.min(Math.max(MIN_TREE, treeW), Math.max(MIN_TREE, hostW * 0.5));
  const inspectorPx = Math.min(splitH - MIN_GRID, Math.max(MIN_INSPECTOR, splitH * inspectorRatio));
  const crumbs = node ? [node.host, ...node.path.split('/').filter(Boolean)] : [];

  return (
    <div className="workspace" style={{ display: active ? 'flex' : 'none', flex: 1, flexDirection: 'column' }}>
      {/* Subtab Navigation Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 4,
          padding: '4px 12px 0 12px',
          background: 'var(--chrome)',
          borderBottom: '1px solid var(--line)',
          flexShrink: 0,
        }}
      >
        <button
          type="button"
          onClick={() => setSubtab('sitemap')}
          style={{
            padding: '5px 14px',
            fontSize: 12,
            fontWeight: subtab === 'sitemap' ? 600 : 500,
            background: subtab === 'sitemap' ? 'var(--panel)' : 'transparent',
            color: subtab === 'sitemap' ? 'var(--text)' : 'var(--text-3)',
            border: '1px solid',
            borderColor: subtab === 'sitemap' ? 'var(--line)' : 'transparent',
            borderBottomColor: subtab === 'sitemap' ? 'var(--panel)' : 'transparent',
            borderTopLeftRadius: 4,
            borderTopRightRadius: 4,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            marginBottom: -1,
          }}
        >
          <Globe size={13} />
          Site map
        </button>

        <button
          type="button"
          onClick={() => setSubtab('scope')}
          style={{
            padding: '5px 14px',
            fontSize: 12,
            fontWeight: subtab === 'scope' ? 600 : 500,
            background: subtab === 'scope' ? 'var(--panel)' : 'transparent',
            color: subtab === 'scope' ? 'var(--text)' : 'var(--text-3)',
            border: '1px solid',
            borderColor: subtab === 'scope' ? 'var(--line)' : 'transparent',
            borderBottomColor: subtab === 'scope' ? 'var(--panel)' : 'transparent',
            borderTopLeftRadius: 4,
            borderTopRightRadius: 4,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            marginBottom: -1,
          }}
        >
          <Shield size={13} style={{ color: scopeCfg.enabled ? 'var(--accent)' : 'inherit' }} />
          Scope
          {scopeCfg.enabled && (
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: 'var(--accent)',
              }}
            />
          )}
        </button>

        <button
          type="button"
          onClick={() => setSubtab('match_replace')}
          style={{
            padding: '5px 14px',
            fontSize: 12,
            fontWeight: subtab === 'match_replace' ? 600 : 500,
            background: subtab === 'match_replace' ? 'var(--panel)' : 'transparent',
            color: subtab === 'match_replace' ? 'var(--text)' : 'var(--text-3)',
            border: '1px solid',
            borderColor: subtab === 'match_replace' ? 'var(--line)' : 'transparent',
            borderBottomColor: subtab === 'match_replace' ? 'var(--panel)' : 'transparent',
            borderTopLeftRadius: 4,
            borderTopRightRadius: 4,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            marginBottom: -1,
          }}
        >
          <Sliders size={13} style={{ color: mrCfg.enabled ? 'var(--accent)' : 'inherit' }} />
          Match and Replace
          {mrCfg.enabled && (
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: 'var(--accent)',
              }}
            />
          )}
        </button>
      </div>

      {/* ==================== SUBTAB 1: SITE MAP ==================== */}
      {subtab === 'sitemap' && (
        <div className="split-h" ref={hostRef} style={{ flex: 1, overflow: 'hidden' }}>
          <div className="pane" style={{ width: treePx, flexShrink: 0 }}>
            <SiteMap
              roots={roots}
              selectedKey={selectedKey}
              onSelect={(n) => {
                setSelectedKey(n.key);
                setSelectedId(null);
              }}
              expanded={expanded}
              onExpanded={(s) => setExpandedList([...s])}
              onClear={clearSitemap}
              footer={
                truncated ? (
                  <div className="trunc-note">
                    <Info size={12} style={{ flexShrink: 0, marginTop: 2 }} />
                    Built from latest {all.length.toLocaleString()} of {total.toLocaleString()} requests.
                  </div>
                ) : null
              }
            />
          </div>
          <Splitter
            orientation="vertical"
            label="Resize site map"
            value={treePx}
            min={MIN_TREE}
            max={Math.max(MIN_TREE, hostW * 0.5)}
            onChange={setTreeW}
            onReset={() => setTreeW(300)}
          />
          <div className="pane" style={{ flex: 1 }}>
            <div className="pane-head" style={{ display: 'flex', justifyContent: 'space-between' }}>
              <nav className="crumbs" aria-label="Selected site map node">
                {crumbs.length ? (
                  crumbs.map((c, i) => (
                    <React.Fragment key={i}>
                      {i > 0 && <ChevronRight size={12} />}
                      <span className={i === crumbs.length - 1 ? 'cur' : undefined}>{c}</span>
                    </React.Fragment>
                  ))
                ) : (
                  <span>Select a host or path</span>
                )}
              </nav>

              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                {scopeCfg.enabled && (
                  <label
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                      fontSize: 11,
                      color: 'var(--text-2)',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={onlyInScope}
                      onChange={(e) => setOnlyInScope(e.target.checked)}
                      style={{ accentColor: 'var(--accent)' }}
                    />
                    Show in-scope only
                  </label>
                )}
                <span className="toolbar-meta">
                  <span>
                    <strong className="num">{rows.length.toLocaleString()}</strong>{' '}
                    {rows.length === 1 ? 'request' : 'requests'}
                  </span>
                </span>
              </div>
            </div>

            <div className="split-v" ref={splitRef}>
              <div className="pane" style={{ flex: 1, minHeight: MIN_GRID }}>
                <HistoryGrid
                  rows={rows}
                  selectedId={selectedId}
                  onSelect={setSelectedId}
                  onMove={move}
                  onClearSelection={() => setSelectedId(null)}
                  sort={sort}
                  onSort={setSort}
                  arrived={new Set()}
                  label="Requests under the selected site map node"
                  loading={items === null && connected !== false}
                  gridRef={gridRef}
                  empty={
                    <div className="state">
                      <h2>{roots.length ? 'Nothing under this node' : 'No hosts discovered yet'}</h2>
                      <p>
                        {roots.length
                          ? onlyInScope
                            ? 'No in-scope requests found under this node. Adjust your Target Scope rules or uncheck "Show in-scope only".'
                            : 'Pick another host or path in the site map.'
                          : 'The site map is built only from requests that passed through the proxy. Browse the target with the proxy enabled.'}
                      </p>
                    </div>
                  }
                />
              </div>
              <Splitter
                orientation="horizontal"
                label="Resize requests and inspector"
                value={inspectorPx}
                min={MIN_INSPECTOR}
                max={splitH - MIN_GRID}
                invert
                onChange={(px) => setInspectorRatio(px / splitH)}
                onReset={() => setInspectorRatio(0.5)}
              />
              <div className="pane" style={{ height: inspectorPx, flexShrink: 0 }}>
                <Inspector
                  summary={summary}
                  detail={detail.state}
                  onRetry={detail.retry}
                  onCopied={onToast}
                  onSendToReplay={onSendToReplay}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================== SUBTAB 2: TARGET SCOPE ==================== */}
      {subtab === 'scope' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 24, background: 'var(--ground)' }}>
          <div style={{ maxWidth: 900, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Scope Control Box */}
            <div
              style={{
                background: 'var(--panel)',
                border: '1px solid var(--line)',
                borderRadius: 6,
                padding: 16,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h2 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Shield size={16} style={{ color: 'var(--accent)' }} /> Target Scope Engine
                  </h2>
                  <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>
                    Define the scope of items you are testing. Out-of-scope traffic can be filtered from the site map or dropped entirely at the proxy boundary.
                  </p>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    className={`btn ${scopeCfg.enabled ? 'primary' : ''}`}
                    onClick={() => saveScope({ ...scopeCfg, enabled: !scopeCfg.enabled })}
                    style={{
                      background: scopeCfg.enabled ? 'var(--accent)' : 'var(--raised)',
                      color: '#fff',
                      padding: '6px 14px',
                      borderRadius: 4,
                      fontSize: 12,
                      fontWeight: 500,
                    }}
                  >
                    {scopeCfg.enabled ? 'Scope Enabled' : 'Scope Disabled'}
                  </button>
                </div>
              </div>

              <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--line)', display: 'flex', flexDirection: 'column', gap: 10 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer', color: 'var(--text)' }}>
                  <input
                    type="checkbox"
                    checked={scopeCfg.drop_out_of_scope}
                    onChange={(e) => saveScope({ ...scopeCfg, drop_out_of_scope: e.target.checked })}
                    style={{ accentColor: 'var(--danger)' }}
                  />
                  <strong style={{ color: scopeCfg.drop_out_of_scope ? 'var(--danger)' : 'inherit' }}>
                    Drop out-of-scope requests immediately (Zero Egress Sandbox)
                  </strong>
                </label>
                <p style={{ fontSize: 11, color: 'var(--text-3)', paddingLeft: 24 }}>
                  When enabled, any HTTP/HTTPS request whose target host or path is out of scope will be immediately aborted with a 403 Forbidden without contacting the remote destination.
                </p>
              </div>
            </div>

            {/* Add Rule Form */}
            <form
              onSubmit={addScopeRule}
              style={{
                background: 'var(--panel)',
                border: '1px solid var(--line)',
                borderRadius: 6,
                padding: 16,
              }}
            >
              <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Plus size={14} /> Add Scope Rule
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '120px 100px 1fr 100px 1fr auto', gap: 8, alignItems: 'center' }}>
                <select
                  value={newRuleType}
                  onChange={(e) => setNewRuleType(e.target.value as ScopeRuleType)}
                  style={{
                    background: 'var(--raised)',
                    border: '1px solid var(--line)',
                    borderRadius: 4,
                    padding: '6px 8px',
                    fontSize: 12,
                  }}
                >
                  <option value="include">Include</option>
                  <option value="exclude">Exclude</option>
                </select>

                <select
                  value={newRuleProto}
                  onChange={(e) => setNewRuleProto(e.target.value)}
                  style={{
                    background: 'var(--raised)',
                    border: '1px solid var(--line)',
                    borderRadius: 4,
                    padding: '6px 8px',
                    fontSize: 12,
                  }}
                >
                  <option value="any">Any proto</option>
                  <option value="https">HTTPS</option>
                  <option value="http">HTTP</option>
                </select>

                <input
                  type="text"
                  placeholder="Host / Pattern (e.g. *.target.com)"
                  value={newRuleHost}
                  onChange={(e) => setNewRuleHost(e.target.value)}
                  style={{
                    background: 'var(--raised)',
                    border: '1px solid var(--line)',
                    borderRadius: 4,
                    padding: '6px 10px',
                    fontSize: 12,
                  }}
                />

                <input
                  type="text"
                  placeholder="Port (opt)"
                  value={newRulePort}
                  onChange={(e) => setNewRulePort(e.target.value)}
                  style={{
                    background: 'var(--raised)',
                    border: '1px solid var(--line)',
                    borderRadius: 4,
                    padding: '6px 10px',
                    fontSize: 12,
                  }}
                />

                <input
                  type="text"
                  placeholder="Path prefix (e.g. /api)"
                  value={newRulePath}
                  onChange={(e) => setNewRulePath(e.target.value)}
                  style={{
                    background: 'var(--raised)',
                    border: '1px solid var(--line)',
                    borderRadius: 4,
                    padding: '6px 10px',
                    fontSize: 12,
                  }}
                />

                <button
                  type="submit"
                  className="btn primary"
                  style={{
                    background: 'var(--accent)',
                    color: '#fff',
                    padding: '6px 14px',
                    borderRadius: 4,
                    fontSize: 12,
                    fontWeight: 500,
                  }}
                >
                  Add
                </button>
              </div>
            </form>

            {/* Scope Rules Table */}
            <div
              style={{
                background: 'var(--panel)',
                border: '1px solid var(--line)',
                borderRadius: 6,
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  padding: '10px 16px',
                  background: 'var(--chrome)',
                  borderBottom: '1px solid var(--line)',
                  fontSize: 12,
                  fontWeight: 600,
                  color: 'var(--text)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <span>Configured Scope Rules ({scopeCfg.rules.length})</span>
                {roots.length > 0 && (
                  <button
                    className="btn"
                    onClick={() => {
                      const newRules: ScopeRule[] = roots.map((r, i) => ({
                        id: `preset_${Date.now()}_${i}`,
                        enabled: true,
                        rule_type: 'include',
                        protocol: null,
                        host: r.host,
                        port: null,
                        path_prefix: null,
                      }));
                      saveScope({
                        ...scopeCfg,
                        enabled: true,
                        rules: [...scopeCfg.rules, ...newRules],
                      });
                    }}
                    style={{
                      fontSize: 11,
                      padding: '3px 8px',
                      background: 'var(--raised)',
                      border: '1px solid var(--line)',
                      borderRadius: 3,
                    }}
                  >
                    Add all current hosts to scope
                  </button>
                )}
              </div>

              {scopeCfg.rules.length === 0 ? (
                <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>
                  No scope rules defined. When scope is enabled without rules, all traffic is considered in-scope.
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--line)', textAlign: 'left', color: 'var(--text-3)' }}>
                      <th style={{ padding: '8px 12px', width: 40 }}>Use</th>
                      <th style={{ padding: '8px 12px', width: 80 }}>Type</th>
                      <th style={{ padding: '8px 12px', width: 80 }}>Protocol</th>
                      <th style={{ padding: '8px 12px' }}>Host / Pattern</th>
                      <th style={{ padding: '8px 12px', width: 80 }}>Port</th>
                      <th style={{ padding: '8px 12px' }}>Path Prefix</th>
                      <th style={{ padding: '8px 12px', width: 50 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {scopeCfg.rules.map((rule) => (
                      <tr
                        key={rule.id}
                        style={{
                          borderBottom: '1px solid var(--line)',
                          opacity: rule.enabled ? 1 : 0.5,
                        }}
                      >
                        <td style={{ padding: '8px 12px' }}>
                          <input
                            type="checkbox"
                            checked={rule.enabled}
                            onChange={() => toggleScopeRule(rule.id)}
                            style={{ accentColor: 'var(--accent)' }}
                          />
                        </td>
                        <td style={{ padding: '8px 12px' }}>
                          <span
                            style={{
                              padding: '2px 6px',
                              borderRadius: 3,
                              fontSize: 10,
                              fontWeight: 600,
                              textTransform: 'uppercase',
                              background: rule.rule_type === 'include' ? 'rgba(76,195,138,0.15)' : 'rgba(240,106,95,0.15)',
                              color: rule.rule_type === 'include' ? 'var(--s2)' : 'var(--s5)',
                            }}
                          >
                            {rule.rule_type}
                          </span>
                        </td>
                        <td style={{ padding: '8px 12px', color: 'var(--text-2)' }}>{rule.protocol || 'Any'}</td>
                        <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
                          {rule.host}
                        </td>
                        <td style={{ padding: '8px 12px', color: 'var(--text-2)' }}>{rule.port ?? 'Any'}</td>
                        <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text-2)' }}>
                          {rule.path_prefix || 'Any'}
                        </td>
                        <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                          <button
                            className="icon-btn"
                            onClick={() => deleteScopeRule(rule.id)}
                            style={{ color: 'var(--text-3)', cursor: 'pointer' }}
                            title="Delete rule"
                          >
                            <Trash2 size={13} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ==================== SUBTAB 3: MATCH AND REPLACE ==================== */}
      {subtab === 'match_replace' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 24, background: 'var(--ground)' }}>
          <div style={{ maxWidth: 960, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Master Control Box */}
            <div
              style={{
                background: 'var(--panel)',
                border: '1px solid var(--line)',
                borderRadius: 6,
                padding: 16,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h2 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Sliders size={16} style={{ color: 'var(--accent)' }} /> Match and Replace Engine
                  </h2>
                  <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>
                    Automatically rewrite headers, request bodies, or response content on-the-fly as traffic passes through the proxy.
                  </p>
                </div>
                <button
                  className={`btn ${mrCfg.enabled ? 'primary' : ''}`}
                  onClick={() => saveMatchReplace({ ...mrCfg, enabled: !mrCfg.enabled })}
                  style={{
                    background: mrCfg.enabled ? 'var(--accent)' : 'var(--raised)',
                    color: '#fff',
                    padding: '6px 14px',
                    borderRadius: 4,
                    fontSize: 12,
                    fontWeight: 500,
                  }}
                >
                  {mrCfg.enabled ? 'Engine Active' : 'Engine Inactive'}
                </button>
              </div>

              {/* Quick Presets */}
              <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--line)' }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-2)', textTransform: 'uppercase' }}>
                  Quick Presets:
                </span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
                  <button
                    className="btn"
                    onClick={() =>
                      applyTemplate({
                        comment: 'Emulate iOS Safari',
                        target: 'request_header',
                        is_regex: true,
                        pattern: '^User-Agent: .*',
                        replacement:
                          'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
                      })
                    }
                    style={{ fontSize: 11, padding: '4px 10px', background: 'var(--raised)', border: '1px solid var(--line)', borderRadius: 3 }}
                  >
                    Emulate iOS Safari
                  </button>
                  <button
                    className="btn"
                    onClick={() =>
                      applyTemplate({
                        comment: 'Emulate Android Chrome',
                        target: 'request_header',
                        is_regex: true,
                        pattern: '^User-Agent: .*',
                        replacement:
                          'User-Agent: Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
                      })
                    }
                    style={{ fontSize: 11, padding: '4px 10px', background: 'var(--raised)', border: '1px solid var(--line)', borderRadius: 3 }}
                  >
                    Emulate Android Chrome
                  </button>
                  <button
                    className="btn"
                    onClick={() =>
                      applyTemplate({
                        comment: 'Strip CSP (Content-Security-Policy)',
                        target: 'response_header',
                        is_regex: true,
                        pattern: '^Content-Security-Policy: .*',
                        replacement: '',
                      })
                    }
                    style={{ fontSize: 11, padding: '4px 10px', background: 'var(--raised)', border: '1px solid var(--line)', borderRadius: 3 }}
                  >
                    Strip CSP
                  </button>
                  <button
                    className="btn"
                    onClick={() =>
                      applyTemplate({
                        comment: 'Strip X-Frame-Options (Clickjacking Testing)',
                        target: 'response_header',
                        is_regex: true,
                        pattern: '^X-Frame-Options: .*',
                        replacement: '',
                      })
                    }
                    style={{ fontSize: 11, padding: '4px 10px', background: 'var(--raised)', border: '1px solid var(--line)', borderRadius: 3 }}
                  >
                    Strip X-Frame-Options
                  </button>
                  <button
                    className="btn"
                    onClick={() =>
                      applyTemplate({
                        comment: 'Inject Security Token',
                        target: 'request_header',
                        is_regex: false,
                        pattern: '',
                        replacement: 'X-DropSuite-Audit: true',
                      })
                    }
                    style={{ fontSize: 11, padding: '4px 10px', background: 'var(--raised)', border: '1px solid var(--line)', borderRadius: 3 }}
                  >
                    Inject Audit Header
                  </button>
                </div>
              </div>
            </div>

            {/* Add Rule Form */}
            <form
              onSubmit={addMatchReplaceRule}
              style={{
                background: 'var(--panel)',
                border: '1px solid var(--line)',
                borderRadius: 6,
                padding: 16,
              }}
            >
              <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Plus size={14} /> Add Match &amp; Replace Rule
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '160px 80px 1fr 1fr 140px auto', gap: 8, alignItems: 'center' }}>
                <select
                  value={newMrTarget}
                  onChange={(e) => setNewMrTarget(e.target.value as MatchReplaceTarget)}
                  style={{
                    background: 'var(--raised)',
                    border: '1px solid var(--line)',
                    borderRadius: 4,
                    padding: '6px 8px',
                    fontSize: 12,
                  }}
                >
                  <option value="request_header">Request Header</option>
                  <option value="request_body">Request Body</option>
                  <option value="response_header">Response Header</option>
                  <option value="response_body">Response Body</option>
                  <option value="request_first_line">Request First Line</option>
                </select>

                <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--text-2)', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={newMrRegex}
                    onChange={(e) => setNewMrRegex(e.target.checked)}
                    style={{ accentColor: 'var(--accent)' }}
                  />
                  Regex
                </label>

                <input
                  type="text"
                  placeholder="Match Pattern (leave empty to add header)"
                  value={newMrPattern}
                  onChange={(e) => setNewMrPattern(e.target.value)}
                  style={{
                    background: 'var(--raised)',
                    border: '1px solid var(--line)',
                    borderRadius: 4,
                    padding: '6px 10px',
                    fontSize: 12,
                  }}
                />

                <input
                  type="text"
                  placeholder="Replacement (leave empty to remove line)"
                  value={newMrReplacement}
                  onChange={(e) => setNewMrReplacement(e.target.value)}
                  style={{
                    background: 'var(--raised)',
                    border: '1px solid var(--line)',
                    borderRadius: 4,
                    padding: '6px 10px',
                    fontSize: 12,
                  }}
                />

                <input
                  type="text"
                  placeholder="Comment / Label"
                  value={newMrComment}
                  onChange={(e) => setNewMrComment(e.target.value)}
                  style={{
                    background: 'var(--raised)',
                    border: '1px solid var(--line)',
                    borderRadius: 4,
                    padding: '6px 10px',
                    fontSize: 12,
                  }}
                />

                <button
                  type="submit"
                  className="btn primary"
                  style={{
                    background: 'var(--accent)',
                    color: '#fff',
                    padding: '6px 14px',
                    borderRadius: 4,
                    fontSize: 12,
                    fontWeight: 500,
                  }}
                >
                  Add
                </button>
              </div>
            </form>

            {/* Match & Replace Rules Table */}
            <div
              style={{
                background: 'var(--panel)',
                border: '1px solid var(--line)',
                borderRadius: 6,
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  padding: '10px 16px',
                  background: 'var(--chrome)',
                  borderBottom: '1px solid var(--line)',
                  fontSize: 12,
                  fontWeight: 600,
                  color: 'var(--text)',
                }}
              >
                Configured Rules ({mrCfg.rules.length})
              </div>

              {mrCfg.rules.length === 0 ? (
                <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>
                  No match &amp; replace rules configured. Add a rule or select a quick preset above.
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--line)', textAlign: 'left', color: 'var(--text-3)' }}>
                      <th style={{ padding: '8px 12px', width: 40 }}>Use</th>
                      <th style={{ padding: '8px 12px', width: 140 }}>Target</th>
                      <th style={{ padding: '8px 12px', width: 60 }}>Regex</th>
                      <th style={{ padding: '8px 12px' }}>Pattern</th>
                      <th style={{ padding: '8px 12px' }}>Replacement</th>
                      <th style={{ padding: '8px 12px', width: 160 }}>Comment</th>
                      <th style={{ padding: '8px 12px', width: 50 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {mrCfg.rules.map((rule) => (
                      <tr
                        key={rule.id}
                        style={{
                          borderBottom: '1px solid var(--line)',
                          opacity: rule.enabled ? 1 : 0.5,
                        }}
                      >
                        <td style={{ padding: '8px 12px' }}>
                          <input
                            type="checkbox"
                            checked={rule.enabled}
                            onChange={() => toggleMatchReplaceRule(rule.id)}
                            style={{ accentColor: 'var(--accent)' }}
                          />
                        </td>
                        <td style={{ padding: '8px 12px', color: 'var(--accent-text)', fontSize: 11 }}>
                          {rule.target.replace(/_/g, ' ')}
                        </td>
                        <td style={{ padding: '8px 12px', color: 'var(--text-3)' }}>{rule.is_regex ? 'Yes' : 'No'}</td>
                        <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
                          {rule.pattern ? (
                            rule.pattern
                          ) : (
                            <span style={{ color: 'var(--text-3)', fontStyle: 'italic' }}>&lt;Add header&gt;</span>
                          )}
                        </td>
                        <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text-2)' }}>
                          {rule.replacement ? (
                            rule.replacement
                          ) : (
                            <span style={{ color: 'var(--danger)', fontStyle: 'italic' }}>&lt;Remove line&gt;</span>
                          )}
                        </td>
                        <td style={{ padding: '8px 12px', color: 'var(--text-3)' }}>{rule.comment}</td>
                        <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                          <button
                            className="icon-btn"
                            onClick={() => deleteMatchReplaceRule(rule.id)}
                            style={{ color: 'var(--text-3)', cursor: 'pointer' }}
                            title="Delete rule"
                          >
                            <Trash2 size={13} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
