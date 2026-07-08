use crate::config::{RiskTier, UpstreamConfig};
use crate::rego_policy::{PolicyInput, RegoPolicy};

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Deny(String),
    RequireApproval,
}

/// Zero-trust default: anything not explicitly reviewed and marked ReadOnly
/// requires a human to say yes. `rego` is optional org-authored policy that
/// can *only* upgrade a RequireApproval verdict to Allow under conditions
/// the org itself defines - it is never consulted for, and can never
/// produce, Blocked or Deny. That boundary is enforced by the match
/// statement below, not by convention: `floor_decision`'s Deny/Allow arms
/// return immediately without `rego` ever being touched.
pub fn evaluate(
    server: &UpstreamConfig,
    tool_name: &str,
    rego: Option<&RegoPolicy>,
    input: Option<&PolicyInput>,
) -> Decision {
    match floor_decision(server, tool_name) {
        Decision::Deny(reason) => Decision::Deny(reason),
        Decision::Allow => Decision::Allow,
        Decision::RequireApproval => {
            if let (Some(rego), Some(input)) = (rego, input) {
                if rego.evaluate(input) {
                    return Decision::Allow;
                }
            }
            Decision::RequireApproval
        }
    }
}

fn floor_decision(server: &UpstreamConfig, tool_name: &str) -> Decision {
    if let Some(policy) = server.tools.get(tool_name) {
        if policy.blocked {
            return Decision::Deny(format!(
                "tool '{tool_name}' is explicitly blocked by policy"
            ));
        }
        return tier_to_decision(policy.risk.unwrap_or(server.default_risk), tool_name);
    }
    // No explicit entry for this tool -> fall back to the server's default
    // tier. An unlisted tool on a server configured `default_risk =
    // "read_only"` runs without confirmation - if you want true default-deny
    // for anything unreviewed, leave default_risk unset (defaults to
    // RequireApproval) and only add ReadOnly entries per tool.
    tier_to_decision(server.default_risk, tool_name)
}

fn tier_to_decision(tier: RiskTier, tool_name: &str) -> Decision {
    match tier {
        RiskTier::Blocked => Decision::Deny(format!("tool '{tool_name}' risk tier is Blocked")),
        RiskTier::ReadOnly => Decision::Allow,
        RiskTier::RequireApproval => Decision::RequireApproval,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ToolPolicy, Transport};
    use std::collections::HashMap;

    fn server_with(default_risk: RiskTier, tools: HashMap<String, ToolPolicy>) -> UpstreamConfig {
        UpstreamConfig {
            id: "test".into(),
            transport: Transport::Stdio {
                command: "true".into(),
                args: vec![],
                env: HashMap::new(),
                sandbox: None,
            },
            default_risk,
            tools,
        }
    }

    fn always_auto_approve_rego() -> RegoPolicy {
        RegoPolicy::compile("package warden\nimport rego.v1\nauto_approve := true").unwrap()
    }

    fn dummy_input() -> PolicyInput {
        PolicyInput {
            server_id: "test".into(),
            tool_name: "delete_everything".into(),
            args_byte_len: 0,
            hour_of_day_utc: 12,
            weekday_utc: 2,
            agent_principal: None,
            agent_purpose: None,
        }
    }

    /// THE core safety invariant this whole design rests on: no matter what
    /// a custom Rego policy says, a Blocked tool stays blocked. This test
    /// existing and passing is not optional.
    #[test]
    fn blocked_tools_ignore_rego_entirely() {
        let mut tools = HashMap::new();
        tools.insert(
            "delete_everything".to_string(),
            ToolPolicy {
                risk: None,
                blocked: true,
            },
        );
        let server = server_with(RiskTier::RequireApproval, tools);
        let rego = always_auto_approve_rego();
        let input = dummy_input();

        let decision = evaluate(&server, "delete_everything", Some(&rego), Some(&input));
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn rego_can_upgrade_require_approval_to_allow() {
        let server = server_with(RiskTier::RequireApproval, HashMap::new());
        let rego = always_auto_approve_rego();
        let input = dummy_input();

        let decision = evaluate(&server, "read_docs", Some(&rego), Some(&input));
        assert!(matches!(decision, Decision::Allow));
    }

    #[test]
    fn rego_eval_error_fails_safe_to_require_approval_not_allow() {
        // A policy that compiles but never defines auto_approve at all.
        let broken = RegoPolicy::compile("package warden\nimport rego.v1\nx := 1").unwrap();
        let server = server_with(RiskTier::RequireApproval, HashMap::new());
        let input = dummy_input();

        let decision = evaluate(&server, "read_docs", Some(&broken), Some(&input));
        assert!(matches!(decision, Decision::RequireApproval));
    }

    #[test]
    fn no_rego_configured_keeps_default_behavior() {
        let server = server_with(RiskTier::RequireApproval, HashMap::new());
        let decision = evaluate(&server, "read_docs", None, None);
        assert!(matches!(decision, Decision::RequireApproval));
    }
}
