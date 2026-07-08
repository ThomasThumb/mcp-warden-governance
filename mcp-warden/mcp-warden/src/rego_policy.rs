use serde::Serialize;
use std::sync::Mutex;

/// Everything the org's Rego policy is allowed to see when deciding whether
/// to auto-approve a call. Deliberately does NOT include a way to express
/// "blocked" or "deny" - the only output this produces is a yes/no on
/// upgrading an already-RequireApproval tool to auto-allowed. See
/// policy.rs::evaluate for where that boundary is enforced in Rust, not Rego.
#[derive(Debug, Serialize)]
pub struct PolicyInput {
    pub server_id: String,
    pub tool_name: String,
    pub args_byte_len: usize,
    pub hour_of_day_utc: u32,
    pub weekday_utc: u32, // 0 = Monday .. 6 = Sunday
    pub agent_principal: Option<String>,
    pub agent_purpose: Option<String>,
}

/// Wraps a compiled Rego module - compiled ONCE at load time, not on every
/// call. An earlier version of this file called `Engine::new()` +
/// `add_policy()` fresh inside `evaluate()`, meaning every single tool call
/// recompiled the whole policy from source text. On a gateway proxying a
/// busy agent that's real, avoidable latency on every RequireApproval-tier
/// call. Caught in self-review, not by an external report - exactly the
/// kind of thing a code-efficiency pass should catch.
pub struct RegoPolicy {
    engine: Mutex<regorus::Engine>,
}

impl RegoPolicy {
    pub fn compile(source: &str) -> anyhow::Result<Self> {
        let mut engine = regorus::Engine::new();
        engine.add_policy("org_policy.rego".to_string(), source.to_string())?;

        // DoS backstop: a pathological or malicious policy (deep
        // comprehensions, unbounded recursion in a `some x in y` walk)
        // could otherwise hang evaluation indefinitely on the gateway's
        // async runtime. VERIFY-AGAINST-DOCS NOTE: this is a *global*
        // fallback (regorus::utils::limits::set_fallback_execution_timer_config),
        // not a per-engine setting - I have real evidence this exact free
        // function exists in regorus's docs, less evidence for a per-engine
        // override, so this is the conservative version. Calling it more
        // than once (e.g. once per compiled policy) is harmless - it just
        // resets the same global limit. If this doesn't compile against
        // your resolved version, removing it still leaves the fail-safe
        // behavior in `evaluate` below intact - a slow policy would hang
        // that one call, not silently allow anything.
        regorus::utils::limits::set_fallback_execution_timer_config(Some(
            regorus::utils::limits::ExecutionTimerConfig {
                limit: std::time::Duration::from_millis(50),
                check_interval: std::num::NonZeroU32::new(1000).unwrap(),
            },
        ));

        Ok(Self {
            engine: Mutex::new(engine),
        })
    }

    /// Returns true only if the org's policy explicitly sets
    /// `data.warden.auto_approve` to true for this input. Any eval error,
    /// timeout, missing rule, or non-boolean result is treated as false -
    /// fail safe, not fail open. This function cannot return anything that
    /// lets a Blocked or unreviewed tool through; policy.rs never even
    /// calls it unless the floor has already said RequireApproval.
    ///
    /// Note this still runs synchronously on whatever tokio worker thread
    /// is handling this call - the 50ms execution cap above bounds how bad
    /// that can get, but a gateway under heavy concurrent load with many
    /// simultaneous RequireApproval-tier calls would still benefit from
    /// moving this onto `spawn_blocking`. Flagged rather than guessed at
    /// blind, since threading that through cleanly touches the Mutex
    /// guard's lifetime across an await point.
    pub fn evaluate(&self, input: &PolicyInput) -> bool {
        let attempt = || -> anyhow::Result<bool> {
            let mut engine = self.engine.lock().unwrap();
            let input_json = serde_json::to_string(input)?;
            engine.set_input(regorus::Value::from_json_str(&input_json)?);
            let results = engine.eval_query("data.warden.auto_approve".to_string(), false)?;
            let value = results
                .result
                .first()
                .and_then(|r| r.expressions.first())
                .map(|e| e.value.clone())
                .ok_or_else(|| anyhow::anyhow!("no auto_approve rule produced a value"))?;
            Ok(matches!(value, regorus::Value::Bool(true)))
        };

        attempt().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "org policy evaluation failed - defaulting to require approval");
            false
        })
    }
}

/// A starter policy showing the kind of thing an org would actually write:
/// auto-approve small, read-tagged calls during business hours from a known
/// agent purpose, require a human for everything else. Ship this as the
/// example in warden.example.toml / warden-cp's org-policy docs, not as a
/// silent default - orgs should have to consciously opt into whatever their
/// own risk tolerance is.
#[allow(dead_code)]
pub const EXAMPLE_POLICY: &str = r#"
package warden

import rego.v1

default auto_approve := false

# Auto-approve small, explicitly read-tagged calls, business hours only,
# and only from an agent session whose purpose we recognize.
auto_approve if {
    startswith(input.tool_name, "read_")
    input.args_byte_len < 2048
    input.hour_of_day_utc >= 13   # 9am-5pm US Eastern, roughly, as UTC
    input.hour_of_day_utc < 21
    input.weekday_utc < 5
    input.agent_purpose == "ci-pipeline"
}
"#;
