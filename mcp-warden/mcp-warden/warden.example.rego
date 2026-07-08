# Copy to warden.rego, point warden.toml's rego_policy_path at it, and adapt.
# This is Rego (Open Policy Agent's language) - real docs at
# https://www.openpolicyagent.org/docs/latest/policy-language/
#
# THE ONE RULE THAT MATTERS: this file can only ever move a tool call from
# "requires human approval" to "auto-approved." It is never consulted for
# Blocked tools, and it cannot deny or block anything itself - that's not a
# convention, mcp-warden's policy.rs enforces it structurally. Write whatever
# rules fit your org; you cannot accidentally open a hole wider than "skip
# some approvals you would've had to click through anyway."

package warden

import rego.v1

default auto_approve := false

# Example 1: small, explicitly read-tagged calls, business hours only, only
# from an agent session whose purpose you recognize.
auto_approve if {
    startswith(input.tool_name, "read_")
    input.args_byte_len < 2048
    input.hour_of_day_utc >= 13
    input.hour_of_day_utc < 21
    input.weekday_utc < 5
    input.agent_purpose == "ci-pipeline"
}

# Example 2: a specific, fully-reviewed tool on a specific server, any time -
# because you've decided this exact combination is genuinely low-risk, not
# because "read" is in the name.
auto_approve if {
    input.server_id == "filesystem"
    input.tool_name == "list_directory"
}

# What NOT to do: don't write a rule like `auto_approve if input.tool_name
# != ""` (i.e. "true unless empty") - it's tempting when approval fatigue
# sets in, but it defeats the entire point. If you're getting swamped,
# that's a signal to write a narrower, real rule for the specific noisy
# tool - not to loosen the net for everything.
