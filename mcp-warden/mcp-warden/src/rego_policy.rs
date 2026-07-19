use serde::Serialize;
use std::sync::{Arc, Mutex};

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
#[derive(Clone)]
pub struct RegoPolicy {
    engine: Arc<Mutex<regorus::Engine>>,
}

impl RegoPolicy {
    pub fn compile(source: &str) -> anyhow::Result<Self> {
        let mut engine = regorus::Engine::new();
        engine.add_policy("org_policy.rego".to_string(), source.to_string())?;

        // DoS backstop: a pathological or malicious policy (deep
        // comprehensions, unbounded recursion in a `some x in y` walk)
        // could otherwise hang evaluation indefinitely on the gateway's
        // async runtime. Regorus currently exposes this as a process-wide
        // fallback rather than a per-engine limit; recompiling a policy just
        // refreshes the same fail-closed timer configuration.
        regorus::utils::limits::set_fallback_execution_timer_config(Some(
            regorus::utils::limits::ExecutionTimerConfig {
                limit: std::time::Duration::from_millis(50),
                check_interval: std::num::NonZeroU32::new(1000)
                    .expect("the policy timer check interval is non-zero"),
            },
        ));

        Ok(Self {
            engine: Arc::new(Mutex::new(engine)),
        })
    }

    /// Returns true only if the org's policy explicitly sets
    /// `data.warden.auto_approve` to true for this input. Any eval error,
    /// timeout, missing rule, or non-boolean result is treated as false -
    /// fail safe, not fail open. This function cannot return anything that
    /// lets a Blocked or unreviewed tool through; policy.rs never even
    /// calls it unless the floor has already said RequireApproval.
    ///
    /// Evaluation is CPU-bound and runs on Tokio's blocking pool so a complex
    /// tenant policy cannot stall unrelated network and MCP tasks.
    pub async fn evaluate(&self, input: &PolicyInput) -> bool {
        let input_json = match serde_json::to_string(input) {
            Ok(input) => input,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize org policy input - defaulting to require approval");
                return false;
            }
        };
        let engine = Arc::clone(&self.engine);
        let attempt = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            let mut engine = engine
                .lock()
                .map_err(|_| anyhow::anyhow!("org policy engine lock is poisoned"))?;
            engine.set_input(regorus::Value::from_json_str(&input_json)?);
            let results = engine.eval_query("data.warden.auto_approve".to_string(), false)?;
            let value = results
                .result
                .first()
                .and_then(|r| r.expressions.first())
                .map(|e| e.value.clone())
                .ok_or_else(|| anyhow::anyhow!("no auto_approve rule produced a value"))?;
            Ok(matches!(value, regorus::Value::Bool(true)))
        })
        .await;

        attempt
            .map_err(|e| anyhow::anyhow!("org policy worker failed: {e}"))
            .and_then(|result| result)
            .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "org policy evaluation failed - defaulting to require approval");
            false
        })
    }
}
