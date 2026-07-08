use regex::RegexSet;

/// First-line heuristic defense against prompt injection / tool poisoning.
///
/// This is deliberately named a "filter", not a "solution" - pattern matching
/// catches known shapes of attack (instruction-override phrasing, exfil URLs,
/// hidden zero-width characters, credential fishing) but a determined attacker
/// can phrase around any fixed rule set. Treat this as one layer: pair it with
/// the integrity guard (catches *changed* tools), the policy engine (limits
/// *blast radius* even if a tool is malicious), and human approval for
/// anything risky. No single layer here is the whole answer.
pub struct InjectionFilter {
    patterns: RegexSet,
    labels: Vec<&'static str>,
    pub block_threshold: u32,
}

impl InjectionFilter {
    pub fn new(block_threshold: u32) -> Self {
        let rules: Vec<(&'static str, &'static str)> = vec![
            (
                "ignore_instructions",
                r"(?i)ignore (all|any|previous|prior|the) (instructions|rules|prompt)",
            ),
            (
                "system_override",
                r"(?i)(you are now|new system prompt|disregard your (instructions|guidelines))",
            ),
            (
                "exfil_request",
                r"(?i)(send|post|email|upload|forward) .{0,60}(to|at) https?://",
            ),
            (
                "credential_probe",
                r"(?i)(api[_-]?key|secret|token|password)\s*[:=]",
            ),
            (
                "hidden_directive",
                r"(?s)<!--.*?-->|[\u{200b}\u{200c}\u{200d}]",
            ),
            ("role_hijack", r"(?i)act as (the )?(system|developer|admin)"),
            (
                "chained_tool_directive",
                r"(?i)before (calling|using|returning) (any )?(other )?(tool|result)",
            ),
            (
                "urgency_pressure",
                r"(?i)(urgent|immediately|do not (tell|inform|notify) the user)",
            ),
        ];
        let patterns = RegexSet::new(rules.iter().map(|(_, p)| *p)).expect("valid regex set");
        let labels = rules.iter().map(|(l, _)| *l).collect();
        Self {
            patterns,
            labels,
            block_threshold,
        }
    }

    /// Returns which rules matched. Run this against tool descriptions/schemas
    /// at capability-fetch time, AND against tool call results/resource content
    /// on the way back - indirect injection usually rides in through data the
    /// server hands back, not the initial tool listing.
    pub fn scan(&self, text: &str) -> Vec<&'static str> {
        self.patterns
            .matches(text)
            .into_iter()
            .map(|i| self.labels[i])
            .collect()
    }

    pub fn score(&self, text: &str) -> u32 {
        self.scan(text).len() as u32
    }

    pub fn should_block(&self, text: &str) -> bool {
        self.score(text) >= self.block_threshold
    }
}
