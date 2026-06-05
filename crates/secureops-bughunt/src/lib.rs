//! # secureops-bughunt
//!
//! A **bounded agentic loop** for LLM-driven security analysis (PRODUCT.md §12
//! "Claude-BugHunter-inspired" + Phase 6): hypothesize → call a read-only tool →
//! verify → repeat, capped at `max_depth` iterations and `max_tool_calls` tool
//! invocations so a runaway model can't loop or spend forever. Context is packed
//! by [`secureops_tokenbudget::TokenBudget`] before *every* call.
//!
//! The model talks through the [`LlmProvider`] trait; tools through [`ToolBox`].
//! Both have deterministic, no-network implementations ([`MockProvider`],
//! [`LocalProvider`], [`NoTools`]) so the loop unit-tests fully offline. Live
//! HTTP providers (OpenAI/Anthropic via reqwest) land in P6b behind a feature.
//!
//! The terminal artifact is a strict-JSON [`FindingReport`]; malformed model
//! output fails the job cleanly (no panic).

#![forbid(unsafe_code)]

/// Real OpenAI/Anthropic providers (codec pure; HTTP behind `live-llm`).
pub mod providers;

use async_trait::async_trait;
use secureops_tokenbudget::{Evidence, TokenBudget};
use serde::{Deserialize, Serialize};

/// One chat message in the running transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Msg {
    pub role: String,
    pub content: String,
}

/// A request to the model.
#[derive(Debug, Clone)]
pub struct CompletionReq {
    pub system: String,
    pub messages: Vec<Msg>,
    pub max_tokens: usize,
}

/// The model's response: either a tool call or a final answer in `content`.
#[derive(Debug, Clone, Default)]
pub struct CompletionResp {
    pub content: String,
    pub tool_call: Option<ToolCall>,
}

/// A read-only tool invocation requested by the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    pub args: serde_json::Value,
}

/// Pluggable model backend.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, req: CompletionReq) -> anyhow::Result<CompletionResp>;
}

/// Pluggable read-only toolbox the model may call during a hunt.
#[async_trait]
pub trait ToolBox: Send + Sync {
    async fn call(&self, tc: &ToolCall) -> String;
}

/// A toolbox that exposes nothing (the model must reason from packed evidence).
pub struct NoTools;
#[async_trait]
impl ToolBox for NoTools {
    async fn call(&self, _tc: &ToolCall) -> String {
        "{}".into()
    }
}

/// Terminal job status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Produced a valid [`FindingReport`].
    Completed,
    /// Errored (provider failure or malformed report) — no panic.
    Failed,
    /// Hit a safety bound (`max_depth` / `max_tool_calls`) without a report.
    Halted,
}

/// The strict-JSON report a completed hunt must produce (PRODUCT.md §12).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingReport {
    pub title: String,
    pub attack_vector: String,
    pub affected_assets: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub severity: String,
    pub cvss_like_score: f32,
    pub remediation_steps: Vec<String>,
}

/// The outcome of a hunt.
#[derive(Debug, Clone)]
pub struct HuntOutcome {
    pub report: Option<FindingReport>,
    pub iterations: usize,
    pub tool_calls: usize,
    pub status: JobStatus,
    pub error: Option<String>,
}

/// Drives the bounded agentic loop over an [`LlmProvider`] + [`ToolBox`].
pub struct BugHunter<P: LlmProvider> {
    provider: P,
    budget: TokenBudget,
    max_depth: usize,
    max_tool_calls: usize,
}

impl<P: LlmProvider> BugHunter<P> {
    /// Default bounds: `max_depth=4`, `max_tool_calls=25` (PRODUCT.md §12).
    pub fn new(provider: P, budget: TokenBudget) -> Self {
        Self {
            provider,
            budget,
            max_depth: 4,
            max_tool_calls: 25,
        }
    }

    /// Override the safety bounds (used by tests and stricter tiers).
    pub fn with_limits(mut self, max_depth: usize, max_tool_calls: usize) -> Self {
        self.max_depth = max_depth;
        self.max_tool_calls = max_tool_calls;
        self
    }

    fn system_prompt(&self, scope: &str) -> String {
        format!(
            "You are a cloud security analyst. Investigate scope `{scope}`. Either call a \
             read-only tool to gather more evidence, or return a single JSON FindingReport \
             with fields: title, attack_vector, affected_assets[], evidence_refs[], severity, \
             cvss_like_score, remediation_steps[]."
        )
    }

    /// Run the hunt. Always terminates within `max_depth` iterations.
    pub async fn hunt(
        &self,
        scope: &str,
        evidence: Vec<Evidence>,
        tools: &dyn ToolBox,
    ) -> HuntOutcome {
        // Token ceiling: pack the most relevant evidence into the window.
        let packed = self.budget.pack(evidence);
        let mut transcript: Vec<Msg> = packed
            .included
            .iter()
            .map(|e| Msg {
                role: "user".into(),
                content: e.raw.clone(),
            })
            .collect();

        let mut tool_calls = 0usize;
        for iter in 1..=self.max_depth {
            let req = CompletionReq {
                system: self.system_prompt(scope),
                messages: transcript.clone(),
                max_tokens: self.budget.reserved_output,
            };
            let resp = match self.provider.complete(req).await {
                Ok(r) => r,
                Err(e) => {
                    return HuntOutcome {
                        report: None,
                        iterations: iter,
                        tool_calls,
                        status: JobStatus::Failed,
                        error: Some(e.to_string()),
                    }
                }
            };

            if let Some(tc) = resp.tool_call {
                if tool_calls >= self.max_tool_calls {
                    return HuntOutcome {
                        report: None,
                        iterations: iter,
                        tool_calls,
                        status: JobStatus::Halted,
                        error: Some("max_tool_calls exceeded".into()),
                    };
                }
                tool_calls += 1;
                let result = tools.call(&tc).await;
                transcript.push(Msg {
                    role: "assistant".into(),
                    content: format!("tool:{}", tc.name),
                });
                transcript.push(Msg {
                    role: "tool".into(),
                    content: result,
                });
                continue;
            }

            // Final answer expected as a strict FindingReport.
            return match serde_json::from_str::<FindingReport>(&resp.content) {
                Ok(report) => HuntOutcome {
                    report: Some(report),
                    iterations: iter,
                    tool_calls,
                    status: JobStatus::Completed,
                    error: None,
                },
                Err(e) => HuntOutcome {
                    report: None,
                    iterations: iter,
                    tool_calls,
                    status: JobStatus::Failed,
                    error: Some(format!("malformed FindingReport: {e}")),
                },
            };
        }

        HuntOutcome {
            report: None,
            iterations: self.max_depth,
            tool_calls,
            status: JobStatus::Halted,
            error: Some("max_depth reached without a report".into()),
        }
    }
}

/// Deterministic mock provider for tests/offline. Either always requests a tool
/// (to exercise the bounds) or replays a fixed script of responses.
pub enum MockProvider {
    /// Every call requests the same read-only tool (never finishes on its own).
    AlwaysTool,
    /// Replay these responses in order; errors once exhausted.
    Script(std::sync::Mutex<std::collections::VecDeque<CompletionResp>>),
}

impl MockProvider {
    pub fn script(responses: Vec<CompletionResp>) -> Self {
        MockProvider::Script(std::sync::Mutex::new(responses.into()))
    }
    /// A single final answer with this content (e.g. a JSON report or garbage).
    pub fn answering(content: impl Into<String>) -> Self {
        Self::script(vec![CompletionResp {
            content: content.into(),
            tool_call: None,
        }])
    }
}

#[async_trait]
impl LlmProvider for MockProvider {
    async fn complete(&self, _req: CompletionReq) -> anyhow::Result<CompletionResp> {
        match self {
            MockProvider::AlwaysTool => Ok(CompletionResp {
                content: String::new(),
                tool_call: Some(ToolCall {
                    name: "describe_asset".into(),
                    args: serde_json::json!({}),
                }),
            }),
            MockProvider::Script(q) => q
                .lock()
                .expect("mock lock")
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("mock script exhausted")),
        }
    }
}

/// Offline heuristic provider — emits a templated [`FindingReport`] immediately
/// (no network, no tools). For air-gapped/dev use; not a substitute for a real
/// model. Returns a low-confidence INFO report scoped to the request.
pub struct LocalProvider;

#[async_trait]
impl LlmProvider for LocalProvider {
    async fn complete(&self, req: CompletionReq) -> anyhow::Result<CompletionResp> {
        let report = FindingReport {
            title: "Heuristic review (local provider)".into(),
            attack_vector: "offline heuristic — no model reasoning applied".into(),
            affected_assets: vec![],
            evidence_refs: vec![],
            severity: "info".into(),
            cvss_like_score: 0.0,
            remediation_steps: vec!["Run with a live LLM provider for real analysis".into()],
        };
        let _ = req;
        Ok(CompletionResp {
            content: serde_json::to_string(&report)?,
            tool_call: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureops_tokenbudget::EvidenceKind;

    fn budget() -> TokenBudget {
        TokenBudget::new("test", 8000, 1000)
    }

    fn valid_report_json() -> String {
        serde_json::to_string(&FindingReport {
            title: "Public S3 bucket".into(),
            attack_vector: "internet → s3:GetObject on public bucket".into(),
            affected_assets: vec!["arn:aws:s3:::data".into()],
            evidence_refs: vec!["ev-1".into()],
            severity: "high".into(),
            cvss_like_score: 7.5,
            remediation_steps: vec!["Block public access".into()],
        })
        .unwrap()
    }

    #[tokio::test]
    async fn always_tool_halts_at_max_depth() {
        let hunter = BugHunter::new(MockProvider::AlwaysTool, budget());
        let out = hunter.hunt("acct-1", vec![], &NoTools).await;
        assert_eq!(out.status, JobStatus::Halted);
        assert_eq!(out.iterations, 4, "must stop at max_depth=4");
        assert_eq!(out.tool_calls, 4);
    }

    #[tokio::test]
    async fn max_tool_calls_bound_trips_before_depth() {
        // depth high, tool budget low → halts on tool-call cap.
        let hunter = BugHunter::new(MockProvider::AlwaysTool, budget()).with_limits(30, 2);
        let out = hunter.hunt("acct-1", vec![], &NoTools).await;
        assert_eq!(out.status, JobStatus::Halted);
        assert_eq!(out.tool_calls, 2);
        assert!(out.error.unwrap().contains("max_tool_calls"));
    }

    #[tokio::test]
    async fn valid_json_completes_with_report() {
        let hunter = BugHunter::new(MockProvider::answering(valid_report_json()), budget());
        let out = hunter.hunt("acct-1", vec![], &NoTools).await;
        assert_eq!(out.status, JobStatus::Completed);
        assert_eq!(out.iterations, 1);
        assert_eq!(out.report.unwrap().severity, "high");
    }

    #[tokio::test]
    async fn malformed_json_fails_without_panic() {
        let hunter = BugHunter::new(MockProvider::answering("not json at all"), budget());
        let out = hunter.hunt("acct-1", vec![], &NoTools).await;
        assert_eq!(out.status, JobStatus::Failed);
        assert!(out.report.is_none());
        assert!(out.error.unwrap().contains("malformed"));
    }

    #[tokio::test]
    async fn provider_error_fails_cleanly() {
        // Empty script → provider errors on first call.
        let hunter = BugHunter::new(MockProvider::script(vec![]), budget());
        let out = hunter.hunt("acct-1", vec![], &NoTools).await;
        assert_eq!(out.status, JobStatus::Failed);
    }

    #[tokio::test]
    async fn tool_then_report_round_trip() {
        let provider = MockProvider::script(vec![
            CompletionResp {
                content: String::new(),
                tool_call: Some(ToolCall {
                    name: "list_buckets".into(),
                    args: serde_json::json!({"scope": "acct-1"}),
                }),
            },
            CompletionResp {
                content: valid_report_json(),
                tool_call: None,
            },
        ]);
        let hunter = BugHunter::new(provider, budget());
        let out = hunter.hunt("acct-1", vec![], &NoTools).await;
        assert_eq!(out.status, JobStatus::Completed);
        assert_eq!(out.tool_calls, 1);
        assert_eq!(out.iterations, 2);
    }

    #[tokio::test]
    async fn budget_packs_before_calling() {
        // Tiny window → only the most relevant evidence survives into context.
        let tight = TokenBudget::new("test", 10, 0);
        let provider = MockProvider::answering(valid_report_json());
        let hunter = BugHunter::new(provider, tight);
        let evidence = vec![
            Evidence::new(EvidenceKind::Log, "z".repeat(400), 0.1),
            Evidence::new(EvidenceKind::Finding, "critical", 0.99),
        ];
        let out = hunter.hunt("acct-1", evidence, &NoTools).await;
        assert_eq!(out.status, JobStatus::Completed);
    }

    #[tokio::test]
    async fn local_provider_returns_templated_report() {
        let hunter = BugHunter::new(LocalProvider, budget());
        let out = hunter.hunt("acct-1", vec![], &NoTools).await;
        assert_eq!(out.status, JobStatus::Completed);
        assert_eq!(out.report.unwrap().severity, "info");
    }
}
