use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use crate::models::TransactionSummary;
use crate::scope::ScopeEngine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteNodeSummary {
    pub key: String,
    pub host: String,
    pub path: String,
    pub name: String,
    pub depth: usize,
    pub in_scope: bool,
    pub total: usize,
    pub status_classes: Vec<String>,
    pub methods: Vec<String>,
    pub parameters: Vec<String>,
    pub children: Vec<SiteNodeSummary>,
}

struct InternalNode {
    key: String,
    host: String,
    path: String,
    name: String,
    depth: usize,
    total: usize,
    status_classes: HashSet<String>,
    methods: HashSet<String>,
    parameters: HashSet<String>,
    children: BTreeMap<String, InternalNode>,
}

impl InternalNode {
    fn new(key: String, host: String, path: String, name: String, depth: usize) -> Self {
        Self {
            key,
            host,
            path,
            name,
            depth,
            total: 0,
            status_classes: HashSet::new(),
            methods: HashSet::new(),
            parameters: HashSet::new(),
            children: BTreeMap::new(),
        }
    }

    fn to_summary(&self, scope: &ScopeEngine) -> SiteNodeSummary {
        let full_target = format!("http://{}{}", self.host, self.path);
        let in_scope = scope.is_in_scope(&full_target);

        let mut status_classes: Vec<String> = self.status_classes.iter().cloned().collect();
        status_classes.sort();

        let mut methods: Vec<String> = self.methods.iter().cloned().collect();
        methods.sort();

        let mut parameters: Vec<String> = self.parameters.iter().cloned().collect();
        parameters.sort();

        let children: Vec<SiteNodeSummary> = self
            .children
            .values()
            .map(|c| c.to_summary(scope))
            .collect();

        SiteNodeSummary {
            key: self.key.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            name: self.name.clone(),
            depth: self.depth,
            in_scope,
            total: self.total,
            status_classes,
            methods,
            parameters,
            children,
        }
    }
}

/// Build a hierarchical site map tree from transaction summaries.
pub fn build_sitemap(items: &[TransactionSummary], scope: &ScopeEngine) -> Vec<SiteNodeSummary> {
    let mut roots: BTreeMap<String, InternalNode> = BTreeMap::new();

    for t in items {
        let host = if t.host.is_empty() { "unknown".to_string() } else { t.host.clone() };
        let root = roots
            .entry(host.clone())
            .or_insert_with(|| InternalNode::new(host.clone(), host.clone(), String::new(), host.clone(), 0));

        let status_class = format!("s{}", t.status_code / 100);
        root.total += 1;
        root.status_classes.insert(status_class.clone());
        root.methods.insert(t.method.clone());

        // Extract path and query params
        let (pathname, query) = if let Some(idx) = t.path.find('?') {
            (&t.path[..idx], &t.path[idx + 1..])
        } else {
            (t.path.as_str(), "")
        };

        let mut params = Vec::new();
        if !query.is_empty() {
            for pair in query.split('&') {
                let k = pair.split('=').next().unwrap_or("").trim();
                if !k.is_empty() {
                    params.push(k.to_string());
                }
            }
        }

        let segments: Vec<&str> = pathname.split('/').filter(|s| !s.is_empty()).collect();
        let mut cur = root;
        let mut path_acc = String::new();

        for (i, seg) in segments.iter().enumerate() {
            path_acc.push('/');
            path_acc.push_str(seg);
            let seg_key = format!("{}{}", cur.host, path_acc);

            cur = cur.children.entry(seg.to_string()).or_insert_with(|| {
                InternalNode::new(seg_key, cur.host.clone(), path_acc.clone(), seg.to_string(), i + 1)
            });

            cur.total += 1;
            cur.status_classes.insert(status_class.clone());
            cur.methods.insert(t.method.clone());
            for p in &params {
                cur.parameters.insert(p.clone());
            }
        }
    }

    roots.values().map(|r| r.to_summary(scope)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_sitemap_hierarchy_and_parameters() {
        let txs = vec![
            TransactionSummary {
                id: 1,
                timestamp: 1000,
                duration_ms: 20,
                method: "GET".into(),
                host: "api.target.com".into(),
                path: "/v1/users?page=1&limit=20".into(),
                status_code: 200,
                content_type: Some("application/json".into()),
                content_length: 50,
            },
            TransactionSummary {
                id: 2,
                timestamp: 2000,
                duration_ms: 50,
                method: "POST".into(),
                host: "api.target.com".into(),
                path: "/v1/users?csrf=abc".into(),
                status_code: 201,
                content_type: Some("application/json".into()),
                content_length: 100,
            },
            TransactionSummary {
                id: 3,
                timestamp: 3000,
                duration_ms: 10,
                method: "GET".into(),
                host: "static.target.com".into(),
                path: "/css/style.css".into(),
                status_code: 200,
                content_type: Some("text/css".into()),
                content_length: 400,
            },
        ];

        let scope = ScopeEngine::new();
        let roots = build_sitemap(&txs, &scope);

        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].host, "api.target.com");
        assert_eq!(roots[0].total, 2);
        assert_eq!(roots[0].children.len(), 1); // "v1"

        let v1 = &roots[0].children[0];
        assert_eq!(v1.name, "v1");
        assert_eq!(v1.children.len(), 1); // "users"

        let users = &v1.children[0];
        assert_eq!(users.name, "users");
        assert_eq!(users.total, 2);
        assert!(users.parameters.contains(&"page".to_string()));
        assert!(users.parameters.contains(&"csrf".to_string()));
    }
}
