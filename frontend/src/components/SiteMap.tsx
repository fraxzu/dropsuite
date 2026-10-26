import React, { useMemo, useRef, useState } from 'react';
import { ChevronDown, ChevronRight, FileText, Folder, Globe, Search, Trash2, X } from 'lucide-react';
import { TransactionSummary } from '../types';
import { displayPath, splitPathQuery, statusClass } from '../lib/http';

export interface SiteNode {
  key: string;
  host: string;
  /** Path prefix this node stands for, '' for the host itself. */
  path: string;
  name: string;
  depth: number;
  children: SiteNode[];
  /** Requests in this subtree. */
  total: number;
  classes: Set<string>;
}

/** Host → path-segment tree, derived only from captured requests. */
export function buildSiteTree(items: TransactionSummary[]): SiteNode[] {
  const hosts = new Map<string, SiteNode>();
  const index = new Map<string, SiteNode>();
  for (const t of items) {
    let host = hosts.get(t.host);
    if (!host) {
      host = { key: t.host, host: t.host, path: '', name: t.host, depth: 0, children: [], total: 0, classes: new Set() };
      hosts.set(t.host, host);
      index.set(host.key, host);
    }
    const sc = statusClass(t.status_code);
    host.total++;
    host.classes.add(sc);
    const { pathname } = splitPathQuery(displayPath(t));
    const segs = pathname.split('/').filter(Boolean);
    let parent = host;
    let prefix = '';
    segs.forEach((seg, i) => {
      prefix += `/${seg}`;
      const key = `${t.host}${prefix}`;
      let node = index.get(key);
      if (!node) {
        node = { key, host: t.host, path: prefix, name: seg, depth: i + 1, children: [], total: 0, classes: new Set() };
        index.set(key, node);
        parent.children.push(node);
      }
      node.total++;
      node.classes.add(sc);
      parent = node;
    });
  }
  const sortRec = (nodes: SiteNode[]) => {
    nodes.sort((a, b) => (a.children.length ? 0 : 1) - (b.children.length ? 0 : 1) || a.name.localeCompare(b.name));
    nodes.forEach((n) => sortRec(n.children));
  };
  const roots = [...hosts.values()];
  sortRec(roots);
  return roots;
}

export function inNode(t: TransactionSummary, node: SiteNode): boolean {
  if (t.host !== node.host) return false;
  if (!node.path) return true;
  const { pathname } = splitPathQuery(displayPath(t));
  return pathname === node.path || pathname.startsWith(`${node.path}/`);
}

interface SiteMapProps {
  roots: SiteNode[];
  selectedKey: string | null;
  onSelect: (node: SiteNode) => void;
  expanded: Set<string>;
  onExpanded: (next: Set<string>) => void;
  footer?: React.ReactNode;
  onClear?: () => void;
}

const DOT_ORDER = ['s2', 's3', 's4', 's5'];

export const SiteMap: React.FC<SiteMapProps> = ({ roots, selectedKey, onSelect, expanded, onExpanded, footer, onClear }) => {
  const [filter, setFilter] = useState('');
  const treeRef = useRef<HTMLDivElement>(null);
  const f = filter.trim().toLowerCase();

  // Flatten what is visible: expanded branches, or every match and its ancestors while filtering.
  const visible = useMemo(() => {
    const out: { node: SiteNode; parent: SiteNode | null }[] = [];
    const matches = (n: SiteNode): boolean => `${n.host}${n.path}`.toLowerCase().includes(f) || n.children.some(matches);
    const walk = (nodes: SiteNode[], parent: SiteNode | null) => {
      for (const n of nodes) {
        if (f && !matches(n)) continue;
        out.push({ node: n, parent });
        if (n.children.length && (f || expanded.has(n.key))) walk(n.children, n);
      }
    };
    walk(roots, null);
    return out;
  }, [roots, expanded, f]);

  const toggle = (key: string) => {
    const next = new Set(expanded);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    onExpanded(next);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    const i = visible.findIndex((v) => v.node.key === selectedKey);
    const cur = visible[i];
    const go = (j: number) => {
      const v = visible[Math.max(0, Math.min(visible.length - 1, j))];
      if (v) {
        onSelect(v.node);
        document.getElementById(`node-${v.node.key}`)?.scrollIntoView({ block: 'nearest' });
      }
    };
    switch (e.key) {
      case 'ArrowDown':
      case 'j':
        go(i + 1);
        break;
      case 'ArrowUp':
      case 'k':
        go(i - 1);
        break;
      case 'Home':
        go(0);
        break;
      case 'End':
        go(visible.length - 1);
        break;
      case 'ArrowRight':
        if (cur?.node.children.length) {
          if (!expanded.has(cur.node.key) && !f) toggle(cur.node.key);
          else go(i + 1);
        }
        break;
      case 'ArrowLeft':
        if (cur && cur.node.children.length && expanded.has(cur.node.key) && !f) toggle(cur.node.key);
        else if (cur?.parent) go(visible.findIndex((v) => v.node.key === cur.parent!.key));
        break;
      case 'Enter':
      case ' ':
        if (cur?.node.children.length) toggle(cur.node.key);
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  };

  const hostCount = roots.length;
  return (
    <div className="sitemap">
      <div className="pane-head">
        <span className="pane-title">Site map</span>
        <span className="pane-sub">
          {hostCount} {hostCount === 1 ? 'host' : 'hosts'}
        </span>
        {onClear && hostCount > 0 && (
          <button
            className="btn sitemap-clear"
            onClick={onClear}
            title="Clear the site map and all captured history (also empties the Proxy history and Scanner)"
          >
            <Trash2 size={12} /> Clear
          </button>
        )}
      </div>
      <div className="tree-filter">
        <div className="search">
          <Search size={13} />
          <input type="search" aria-label="Filter site map" placeholder="Filter hosts and paths" value={filter} spellCheck={false} onChange={(e) => setFilter(e.target.value)} />
          {filter && (
            <button className="icon-btn clear" aria-label="Clear site map filter" onClick={() => setFilter('')}>
              <X size={12} />
            </button>
          )}
        </div>
      </div>
      <div
        ref={treeRef}
        className="tree"
        role="tree"
        aria-label="Site map"
        tabIndex={0}
        aria-activedescendant={selectedKey ? `node-${selectedKey}` : undefined}
        onKeyDown={onKeyDown}
      >
        {visible.length === 0 ? (
          <div className="body-empty">{roots.length ? 'No hosts or paths match this filter.' : 'Hosts and paths appear here as traffic is captured. Nothing is guessed or crawled.'}</div>
        ) : (
          visible.map(({ node }) => {
            const open = !!f || expanded.has(node.key);
            const branch = node.children.length > 0;
            const Icon = node.depth === 0 ? Globe : branch ? Folder : FileText;
            return (
              <div
                key={node.key}
                id={`node-${node.key}`}
                role="treeitem"
                aria-level={node.depth + 1}
                aria-expanded={branch ? open : undefined}
                aria-selected={node.key === selectedKey}
                className={`tree-item${node.depth === 0 ? ' host' : ''}`}
                style={{ paddingLeft: 6 + node.depth * 14 }}
                onMouseDown={() => onSelect(node)}
                onDoubleClick={() => branch && toggle(node.key)}
              >
                <span
                  className="twisty"
                  onMouseDown={(e) => {
                    if (!branch) return;
                    e.stopPropagation();
                    toggle(node.key);
                  }}
                >
                  {branch ? open ? <ChevronDown size={13} /> : <ChevronRight size={13} /> : null}
                </span>
                <Icon size={13} className="node-icon" />
                <span className={`label${/^[0-9a-f-]{3,}$/i.test(node.name) && /\d/.test(node.name) && node.depth > 0 ? ' param' : ''}`}>{node.name}</span>
                <span className="status-dots" aria-hidden="true">
                  {DOT_ORDER.filter((c) => node.classes.has(c)).map((c) => (
                    <i key={c} className={c} />
                  ))}
                </span>
                <span className="count">{node.total}</span>
              </div>
            );
          })
        )}
      </div>
      {footer}
    </div>
  );
};
