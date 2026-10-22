//! Intruder: automated request fuzzing built *on top of* [`crate::replay`].
//!
//! Intruder takes one base request with position markers, a set of payloads, and fires many
//! requests with those payloads substituted in. Because it is an automated mass sender, a single
//! design slip turns it into an SSRF cannon or a flooder. The six guarantees below are therefore
//! **acceptance criteria**, encoded as tests at the bottom of this file — not options:
//!
//! 1. **Reuse the Replay send path, never fork it.** Every request goes through [`replay::send`],
//!    which already resolves once and checks `is_restricted_destination` (link-local, cloud
//!    metadata `169.254.169.254`, multicast, …) before opening a socket, with timeouts and memory
//!    sanitation. Intruder adds no new egress path. (see `reuses_replay_guard_blocks_link_local`)
//! 2. **Respect Scope.** A rendered target that is out of scope is reported and **not sent**.
//!    (see `out_of_scope_target_is_not_sent`)
//! 3. **Concurrency limit + throttle.** A hard-capped concurrency ceiling *and* an optional delay
//!    between dispatches — both, not either. (see `effective_concurrency_is_clamped`)
//! 4. **Hard cancel.** A shared flag stops further dispatch at once; in-flight requests drain.
//! 5. **Bounded memory.** Responses are reduced to a compact [`AttemptSummary`] and streamed over a
//!    channel; full bodies are never retained. The plan size is capped before any send.
//!    (see `rejects_plan_over_max_attempts`)
//! 6. **MVP attack types: Sniper + Cluster Bomb only.** Pitchfork / Battering Ram come later.
//!
//! Position markers use DropSuite's own delimiter `{{ ... }}` — deliberately **not** Burp's `§`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Semaphore};

use crate::replay::{self, ReplayError, ReplayOptions, ReplayRequest};
use crate::scope::ScopeEngine;

/// Marker delimiters. Our own, not PortSwigger's `§`.
const OPEN: &str = "{{";
const CLOSE: &str = "}}";

/// Never run more than this many requests at once, whatever the caller asks for (criterion 3).
pub const HARD_MAX_CONCURRENCY: usize = 32;
/// Refuse a plan larger than this many attempts (criterion 5).
pub const HARD_MAX_ATTEMPTS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntruderError {
    pub kind: &'static str,
    pub message: String,
}

impl IntruderError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl std::fmt::Display for IntruderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

// --------------------------------------------------------------------------------------------
// Payloads
// --------------------------------------------------------------------------------------------

/// One source of payload values for a position.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadSet {
    /// An explicit list / wordlist.
    List { values: Vec<String> },
    /// An inclusive numeric range with a non-zero step.
    NumberRange { from: i64, to: i64, step: i64 },
}

impl PayloadSet {
    pub fn values(&self) -> Result<Vec<String>, IntruderError> {
        match self {
            PayloadSet::List { values } => Ok(values.clone()),
            PayloadSet::NumberRange { from, to, step } => {
                if *step == 0 {
                    return Err(IntruderError::new("invalid", "Number range step cannot be 0."));
                }
                let mut out = Vec::new();
                let mut n = *from;
                if *step > 0 {
                    while n <= *to {
                        out.push(n.to_string());
                        n += *step;
                    }
                } else {
                    while n >= *to {
                        out.push(n.to_string());
                        n += *step;
                    }
                }
                Ok(out)
            }
        }
    }

    pub fn len(&self) -> Result<usize, IntruderError> {
        Ok(self.values()?.len())
    }

    pub fn is_empty(&self) -> Result<bool, IntruderError> {
        Ok(self.len()? == 0)
    }
}

/// Which attack shape to run across the parsed positions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Attack {
    /// One payload set applied to each position in turn; every other position keeps its base text.
    /// `positions × payloads` attempts.
    Sniper { payloads: PayloadSet },
    /// One payload set per position, Cartesian product across all positions.
    /// `payload_sets.len()` must equal the number of positions.
    ClusterBomb { payload_sets: Vec<PayloadSet> },
}

// --------------------------------------------------------------------------------------------
// Template parsing / rendering
// --------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Segment {
    Literal(String),
    Slot(usize),
}

#[derive(Debug, Clone)]
struct Field {
    segments: Vec<Segment>,
}

/// Percent-encode everything except the URL unreserved set, so a payload with spaces or special
/// characters is a valid URL component instead of breaking the request.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl Field {
    /// Render the field. When `encode` is set, each substituted payload is percent-encoded (used
    /// for positions inside the URL); literal text is always left as written.
    fn render(&self, repl: &[String], encode: bool) -> String {
        let mut out = String::new();
        for seg in &self.segments {
            match seg {
                Segment::Literal(s) => out.push_str(s),
                Segment::Slot(i) => {
                    if encode {
                        out.push_str(&percent_encode(&repl[*i]));
                    } else {
                        out.push_str(&repl[*i]);
                    }
                }
            }
        }
        out
    }
}

/// A base request with its `{{ }}` positions parsed out, ready to render with concrete payloads.
#[derive(Debug, Clone)]
pub struct Template {
    method: String,
    url: Field,
    header_names: Vec<String>,
    header_values: Vec<Field>,
    body: Field,
    /// Base text found inside each marker, in position order (used for Sniper's inactive slots).
    bases: Vec<String>,
}

impl Template {
    /// Parse `{{ }}` markers across the URL, every header value, and the body.
    /// Positions are numbered left to right in that order.
    pub fn parse(req: &ReplayRequest) -> Template {
        let mut bases: Vec<String> = Vec::new();
        let url = tokenize(&req.url, &mut bases);
        let mut header_names = Vec::with_capacity(req.headers.len());
        let mut header_values = Vec::with_capacity(req.headers.len());
        for (name, value) in &req.headers {
            header_names.push(name.clone());
            header_values.push(tokenize(value, &mut bases));
        }
        let body = tokenize(&req.body, &mut bases);
        Template {
            method: req.method.clone(),
            url,
            header_names,
            header_values,
            body,
            bases,
        }
    }

    pub fn position_count(&self) -> usize {
        self.bases.len()
    }

    fn render(&self, repl: &[String], encode_url: bool) -> ReplayRequest {
        let headers = self
            .header_names
            .iter()
            .cloned()
            .zip(self.header_values.iter().map(|f| f.render(repl, false)))
            .collect();
        ReplayRequest {
            method: self.method.clone(),
            url: self.url.render(repl, encode_url),
            headers,
            body: self.body.render(repl, false),
        }
    }
}

/// Split one string into literal/slot segments, appending each marker's base text to `bases`.
/// An unterminated `{{` is treated as literal text, so stray braces never break a request.
fn tokenize(input: &str, bases: &mut Vec<String>) -> Field {
    let mut segments = Vec::new();
    let mut rest = input;
    while let Some(open) = rest.find(OPEN) {
        let after_open = &rest[open + OPEN.len()..];
        match after_open.find(CLOSE) {
            Some(close) => {
                if open > 0 {
                    segments.push(Segment::Literal(rest[..open].to_string()));
                }
                let base = after_open[..close].to_string();
                segments.push(Segment::Slot(bases.len()));
                bases.push(base);
                rest = &after_open[close + CLOSE.len()..];
            }
            None => break, // no closing marker: the remainder is literal
        }
    }
    if !rest.is_empty() {
        segments.push(Segment::Literal(rest.to_string()));
    }
    Field { segments }
}

// --------------------------------------------------------------------------------------------
// Plan building
// --------------------------------------------------------------------------------------------

/// Build the list of per-slot replacement vectors the attack will send, after validating the
/// attack against the template and enforcing the attempt cap (criterion 5).
fn build_jobs(
    template: &Template,
    attack: &Attack,
    max_attempts: usize,
) -> Result<Vec<Vec<String>>, IntruderError> {
    let p = template.position_count();
    if p == 0 {
        return Err(IntruderError::new(
            "no_positions",
            "No {{ }} positions in the request. Mark at least one.",
        ));
    }
    let cap = max_attempts.min(HARD_MAX_ATTEMPTS);

    let planned = plan_size(template, attack)?;
    if planned > cap {
        return Err(IntruderError::new(
            "too_many",
            format!("Plan is {planned} attempts, over the limit of {cap}. Narrow the payload set."),
        ));
    }

    let mut jobs: Vec<Vec<String>> = Vec::new();
    match attack {
        Attack::Sniper { payloads } => {
            let values = payloads.values()?;
            for pos in 0..p {
                for v in &values {
                    let mut repl = template.bases.clone();
                    repl[pos] = v.clone();
                    jobs.push(repl);
                }
            }
        }
        Attack::ClusterBomb { payload_sets } => {
            let value_sets: Vec<Vec<String>> =
                payload_sets.iter().map(|s| s.values()).collect::<Result<_, _>>()?;
            cartesian(&value_sets, &mut jobs);
        }
    }
    Ok(jobs)
}

/// Validate a base request + attack and return how many attempts it would produce, cheaply
/// (without materializing any request). Fails the same way [`build_jobs`] would: `no_positions`,
/// `mismatch`, `invalid`, or `too_many`. Use this to reject or size a run before starting it.
pub fn planned_attempts(
    base: &ReplayRequest,
    attack: &Attack,
    max_attempts: usize,
) -> Result<usize, IntruderError> {
    let template = Template::parse(base);
    if template.position_count() == 0 {
        return Err(IntruderError::new(
            "no_positions",
            "No {{ }} positions in the request. Mark at least one.",
        ));
    }
    let planned = plan_size(&template, attack)?;
    let cap = max_attempts.min(HARD_MAX_ATTEMPTS);
    if planned > cap {
        return Err(IntruderError::new(
            "too_many",
            format!("Plan is {planned} attempts, over the limit of {cap}. Narrow the payload set."),
        ));
    }
    Ok(planned)
}

/// Compute how many attempts an attack would produce without materializing them.
fn plan_size(template: &Template, attack: &Attack) -> Result<usize, IntruderError> {
    let p = template.position_count();
    match attack {
        Attack::Sniper { payloads } => Ok(p.saturating_mul(payloads.len()?)),
        Attack::ClusterBomb { payload_sets } => {
            if payload_sets.len() != p {
                return Err(IntruderError::new(
                    "mismatch",
                    format!("Cluster bomb needs one payload set per position ({p}); got {}.", payload_sets.len()),
                ));
            }
            let mut total: usize = 1;
            for s in payload_sets {
                total = total.saturating_mul(s.len()?);
            }
            Ok(total)
        }
    }
}

fn cartesian(sets: &[Vec<String>], out: &mut Vec<Vec<String>>) {
    if sets.iter().any(|s| s.is_empty()) {
        return;
    }
    let mut current = vec![0usize; sets.len()];
    loop {
        out.push(sets.iter().zip(&current).map(|(s, &i)| s[i].clone()).collect());
        // increment mixed-radix counter
        let mut k = sets.len();
        loop {
            if k == 0 {
                return;
            }
            k -= 1;
            current[k] += 1;
            if current[k] < sets[k].len() {
                break;
            }
            current[k] = 0;
        }
    }
}

// --------------------------------------------------------------------------------------------
// Running
// --------------------------------------------------------------------------------------------

/// Caller-tunable guards. `max_concurrency` is clamped to [`HARD_MAX_CONCURRENCY`]; `max_attempts`
/// to [`HARD_MAX_ATTEMPTS`].
pub struct Guards {
    pub max_concurrency: usize,
    pub delay_between: Duration,
    pub max_attempts: usize,
    /// Percent-encode payloads substituted into URL positions, so values with spaces or special
    /// characters stay valid URLs instead of failing to send.
    pub encode_url: bool,
}

impl Default for Guards {
    fn default() -> Self {
        Self {
            max_concurrency: 8,
            delay_between: Duration::ZERO,
            max_attempts: 10_000,
            encode_url: false,
        }
    }
}

/// Clamp a requested concurrency to a sane, non-zero, hard-capped value (criterion 3).
pub fn effective_concurrency(requested: usize) -> usize {
    requested.clamp(1, HARD_MAX_CONCURRENCY)
}

/// A finished attempt, compact on purpose (criterion 5: no response bodies retained).
#[derive(Debug, Clone)]
pub struct AttemptSummary {
    pub status: u16,
    pub total_bytes: u64,
    pub duration_ms: u64,
    pub destination: String,
    /// Set when the answer was a bot challenge, so a fuzzer run is not read as real results.
    pub challenge: Option<crate::challenge::ChallengeSignal>,
}

/// One streamed result. `result` carries the Replay error as-is, so e.g. the destination-policy
/// block surfaces here as `kind == "blocked"`, and an out-of-scope skip as `kind == "scope"`.
#[derive(Debug, Clone)]
pub struct AttemptOutcome {
    pub index: usize,
    pub replacements: Vec<String>,
    pub result: Result<AttemptSummary, ReplayError>,
}

#[derive(Debug, Clone, Default)]
pub struct RunStats {
    pub planned: usize,
    pub dispatched: usize,
    pub scope_skipped: usize,
    pub cancelled: bool,
}

/// Run the attack. Outcomes stream over `out` as they finish; the returned [`RunStats`] summarizes
/// the dispatch. Set `cancel` to stop further dispatch (criterion 4); in-flight requests drain.
pub async fn run(
    base: &ReplayRequest,
    attack: &Attack,
    opts: ReplayOptions,
    scope: &ScopeEngine,
    guards: &Guards,
    cancel: Arc<AtomicBool>,
    out: mpsc::Sender<AttemptOutcome>,
) -> Result<RunStats, IntruderError> {
    let template = Template::parse(base);
    let jobs = build_jobs(&template, attack, guards.max_attempts)?;

    let mut stats = RunStats { planned: jobs.len(), ..Default::default() };
    let sem = Arc::new(Semaphore::new(effective_concurrency(guards.max_concurrency)));
    let opts = Arc::new(opts);
    let mut handles = Vec::new();

    for (index, repl) in jobs.into_iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            stats.cancelled = true;
            break;
        }
        let req = template.render(&repl, guards.encode_url);

        // Criterion 2: out-of-scope targets are reported but never sent.
        if !scope.is_in_scope(&req.url) {
            stats.scope_skipped += 1;
            let _ = out
                .send(AttemptOutcome {
                    index,
                    replacements: repl,
                    result: Err(ReplayError::new("scope", "Target is out of scope; not sent.")),
                })
                .await;
            continue;
        }

        // Criterion 3: throttle between dispatches, then take a concurrency permit.
        if guards.delay_between > Duration::ZERO {
            tokio::time::sleep(guards.delay_between).await;
        }
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        stats.dispatched += 1;

        let opts = opts.clone();
        let tx = out.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            // Criterion 1: the ONLY egress path is replay::send, which runs the destination guard.
            let result = replay::send(&req, &opts).await.map(|r| AttemptSummary {
                status: r.status,
                total_bytes: r.total_bytes,
                duration_ms: r.duration_ms,
                destination: r.destination,
                challenge: r.challenge,
            });
            let _ = tx.send(AttemptOutcome { index, replacements: repl, result }).await;
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    Ok(stats)
}

// --------------------------------------------------------------------------------------------
// Tests — these encode the acceptance criteria.
// --------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, url: &str, body: &str) -> ReplayRequest {
        ReplayRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: Vec::new(),
            body: body.to_string(),
        }
    }

    #[test]
    fn parses_custom_delimiter_and_ignores_section_sign() {
        // `{{ }}` is a position; `§` is just a literal character (not Burp's marker).
        let t = Template::parse(&req("GET", "http://t/u?x={{admin}}&y=§notmarker§", "id={{1}}"));
        assert_eq!(t.position_count(), 2);
        assert_eq!(t.bases, vec!["admin".to_string(), "1".to_string()]);
        let rendered = t.render(&["root".to_string(), "99".to_string()], false);
        assert_eq!(rendered.url, "http://t/u?x=root&y=§notmarker§");
        assert_eq!(rendered.body, "id=99");
    }

    #[test]
    fn unterminated_marker_stays_literal() {
        let t = Template::parse(&req("GET", "http://t/{{oops", ""));
        assert_eq!(t.position_count(), 0);
        assert_eq!(t.render(&[], false).url, "http://t/{{oops");
    }

    #[test]
    fn url_payloads_are_percent_encoded_when_enabled() {
        let t = Template::parse(&req("GET", "http://t/s?q={{x}}", ""));
        assert_eq!(t.render(&["a b'--".to_string()], true).url, "http://t/s?q=a%20b%27--");
        assert_eq!(t.render(&["a b'--".to_string()], false).url, "http://t/s?q=a b'--");
    }

    #[test]
    fn sniper_is_positions_times_payloads() {
        let t = Template::parse(&req("GET", "http://t/{{a}}/{{b}}", ""));
        let attack = Attack::Sniper {
            payloads: PayloadSet::List { values: vec!["1".into(), "2".into(), "3".into()] },
        };
        let jobs = build_jobs(&t, &attack, 1000).unwrap();
        assert_eq!(jobs.len(), 2 * 3);
        // First job: position 0 gets "1", position 1 keeps its base "b".
        assert_eq!(jobs[0], vec!["1".to_string(), "b".to_string()]);
    }

    #[test]
    fn cluster_bomb_is_cartesian() {
        let t = Template::parse(&req("GET", "http://t/{{a}}/{{b}}", ""));
        let attack = Attack::ClusterBomb {
            payload_sets: vec![
                PayloadSet::List { values: vec!["x".into(), "y".into()] },
                PayloadSet::NumberRange { from: 1, to: 3, step: 1 },
            ],
        };
        let jobs = build_jobs(&t, &attack, 1000).unwrap();
        assert_eq!(jobs.len(), 2 * 3);
        assert_eq!(jobs[0], vec!["x".to_string(), "1".to_string()]);
        assert_eq!(jobs[5], vec!["y".to_string(), "3".to_string()]);
    }

    #[test]
    fn cluster_bomb_rejects_wrong_set_count() {
        let t = Template::parse(&req("GET", "http://t/{{a}}/{{b}}", ""));
        let attack = Attack::ClusterBomb {
            payload_sets: vec![PayloadSet::List { values: vec!["x".into()] }], // 1 set for 2 positions
        };
        assert_eq!(build_jobs(&t, &attack, 1000).unwrap_err().kind, "mismatch");
    }

    #[test]
    fn rejects_plan_over_max_attempts() {
        // Criterion 5: the plan is capped before anything is sent.
        let t = Template::parse(&req("GET", "http://t/{{a}}", ""));
        let attack = Attack::Sniper {
            payloads: PayloadSet::NumberRange { from: 1, to: 1000, step: 1 },
        };
        assert_eq!(build_jobs(&t, &attack, 10).unwrap_err().kind, "too_many");
    }

    #[test]
    fn effective_concurrency_is_clamped() {
        // Criterion 3: never below 1, never above the hard cap.
        assert_eq!(effective_concurrency(0), 1);
        assert_eq!(effective_concurrency(8), 8);
        assert_eq!(effective_concurrency(10_000), HARD_MAX_CONCURRENCY);
    }

    #[tokio::test]
    async fn out_of_scope_target_is_not_sent() {
        // Criterion 2: scope enabled with an Include rule that does not match the target.
        use crate::scope::{ScopeConfig, ScopeRule, ScopeRuleType};
        let scope = ScopeEngine::with_config(ScopeConfig {
            enabled: true,
            drop_out_of_scope: false,
            rules: vec![ScopeRule {
                id: "1".into(),
                enabled: true,
                rule_type: ScopeRuleType::Include,
                protocol: None,
                host: "only.example.com".into(),
                port: None,
                path_prefix: None,
            }],
        });
        let base = req("GET", "http://other.test/{{a}}", "");
        let attack = Attack::Sniper { payloads: PayloadSet::List { values: vec!["p".into()] } };
        let (tx, mut rx) = mpsc::channel(8);
        let stats = run(
            &base,
            &attack,
            ReplayOptions {
                connect_timeout: Duration::from_secs(2),
                response_timeout: Duration::from_secs(2),
                own_listener: None,
                tls_roots: Vec::new(),
        apply: crate::replay::ApplyConfig::default(),
            },
            &scope,
            &Guards::default(),
            Arc::new(AtomicBool::new(false)),
            tx,
        )
        .await
        .unwrap();

        assert_eq!(stats.dispatched, 0);
        assert_eq!(stats.scope_skipped, 1);
        let outcome = rx.recv().await.unwrap();
        assert_eq!(outcome.result.unwrap_err().kind, "scope");
    }

    #[tokio::test]
    async fn reuses_replay_guard_blocks_link_local() {
        // Criterion 1: an in-scope link-local target is still blocked, because the one egress path
        // is replay::send and it runs is_restricted_destination before connecting. No real egress.
        let scope = ScopeEngine::new(); // empty => everything in scope
        let base = req("GET", "http://169.254.169.254/{{a}}", "");
        let attack = Attack::Sniper { payloads: PayloadSet::List { values: vec!["latest".into()] } };
        let (tx, mut rx) = mpsc::channel(8);
        let stats = run(
            &base,
            &attack,
            ReplayOptions {
                connect_timeout: Duration::from_secs(2),
                response_timeout: Duration::from_secs(2),
                own_listener: None,
                tls_roots: Vec::new(),
        apply: crate::replay::ApplyConfig::default(),
            },
            &scope,
            &Guards::default(),
            Arc::new(AtomicBool::new(false)),
            tx,
        )
        .await
        .unwrap();

        assert_eq!(stats.dispatched, 1);
        let outcome = rx.recv().await.unwrap();
        assert_eq!(outcome.result.unwrap_err().kind, "blocked");
    }
}
