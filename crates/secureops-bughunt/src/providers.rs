//! Real LLM providers (PRODUCT.md Phase 6/6b). The request-building and
//! response-parsing **codecs are pure** (no network) and always compiled +
//! tested; the actual HTTP `complete()` call is gated behind the `live-llm`
//! feature (reqwest), so the default build stays light and offline-testable.

use serde_json::{json, Value};

use crate::{CompletionReq, CompletionResp, ToolCall};

/// OpenAI Chat Completions provider.
pub struct OpenAiProvider {
    pub api_key: String,
    pub model: String,
    pub base_url: String,
}

impl OpenAiProvider {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            model: model.into(),
            base_url: "https://api.openai.com/v1".into(),
        }
    }

    /// Build the Chat Completions request body (pure).
    pub fn build_body(&self, req: &CompletionReq) -> Value {
        let mut messages = vec![json!({ "role": "system", "content": req.system })];
        for m in &req.messages {
            messages.push(json!({ "role": m.role, "content": m.content }));
        }
        json!({
            "model": self.model,
            "max_tokens": req.max_tokens,
            "messages": messages,
        })
    }

    /// Parse a Chat Completions response into a [`CompletionResp`] (pure).
    pub fn parse(resp: &Value) -> CompletionResp {
        let message = &resp["choices"][0]["message"];
        let tool_call = message["tool_calls"][0]["function"].as_object().map(|f| {
            let name = f
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args = f
                .get("arguments")
                .and_then(|v| v.as_str())
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(Value::Object(Default::default()));
            ToolCall { name, args }
        });
        CompletionResp {
            content: message["content"].as_str().unwrap_or("").to_string(),
            tool_call,
        }
    }
}

/// Anthropic Messages provider.
pub struct AnthropicProvider {
    pub api_key: String,
    pub model: String,
    pub base_url: String,
}

impl AnthropicProvider {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            model: model.into(),
            base_url: "https://api.anthropic.com/v1".into(),
        }
    }

    /// Build the Messages request body (pure). `system` is a top-level field.
    pub fn build_body(&self, req: &CompletionReq) -> Value {
        let messages: Vec<Value> = req
            .messages
            .iter()
            .map(|m| json!({ "role": m.role, "content": m.content }))
            .collect();
        json!({
            "model": self.model,
            "max_tokens": req.max_tokens,
            "system": req.system,
            "messages": messages,
        })
    }

    /// Parse a Messages response into a [`CompletionResp`] (pure). Picks the
    /// first `text` block as content and the first `tool_use` block as a tool call.
    pub fn parse(resp: &Value) -> CompletionResp {
        let mut content = String::new();
        let mut tool_call = None;
        if let Some(blocks) = resp["content"].as_array() {
            for b in blocks {
                match b["type"].as_str() {
                    Some("text") if content.is_empty() => {
                        content = b["text"].as_str().unwrap_or("").to_string();
                    }
                    Some("tool_use") if tool_call.is_none() => {
                        tool_call = Some(ToolCall {
                            name: b["name"].as_str().unwrap_or("").to_string(),
                            args: b["input"].clone(),
                        });
                    }
                    _ => {}
                }
            }
        }
        CompletionResp { content, tool_call }
    }
}

// ---------------------------------------------------------------------------
// Live HTTP implementations (gated — pull reqwest only with `live-llm`).
// ---------------------------------------------------------------------------

#[cfg(feature = "live-llm")]
mod live {
    use super::*;
    use crate::LlmProvider;
    use async_trait::async_trait;

    #[async_trait]
    impl LlmProvider for OpenAiProvider {
        async fn complete(&self, req: CompletionReq) -> anyhow::Result<CompletionResp> {
            let body = self.build_body(&req);
            let resp: Value = reqwest::Client::new()
                .post(format!("{}/chat/completions", self.base_url))
                .bearer_auth(&self.api_key)
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            Ok(OpenAiProvider::parse(&resp))
        }
    }

    #[async_trait]
    impl LlmProvider for AnthropicProvider {
        async fn complete(&self, req: CompletionReq) -> anyhow::Result<CompletionResp> {
            let body = self.build_body(&req);
            let resp: Value = reqwest::Client::new()
                .post(format!("{}/messages", self.base_url))
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            Ok(AnthropicProvider::parse(&resp))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Msg;

    fn req() -> CompletionReq {
        CompletionReq {
            system: "sys".into(),
            messages: vec![Msg {
                role: "user".into(),
                content: "find bugs".into(),
            }],
            max_tokens: 512,
        }
    }

    #[test]
    fn openai_body_shape() {
        let p = OpenAiProvider::new("sk", "gpt-4o");
        let b = p.build_body(&req());
        assert_eq!(b["model"], "gpt-4o");
        assert_eq!(b["max_tokens"], 512);
        assert_eq!(b["messages"][0]["role"], "system");
        assert_eq!(b["messages"][1]["content"], "find bugs");
    }

    #[test]
    fn openai_parse_content_and_tool_call() {
        let text = json!({ "choices": [ { "message": { "content": "hello" } } ] });
        assert_eq!(OpenAiProvider::parse(&text).content, "hello");

        let tool = json!({ "choices": [ { "message": {
            "content": null,
            "tool_calls": [ { "function": { "name": "list_buckets", "arguments": "{\"scope\":\"all\"}" } } ]
        } } ] });
        let r = OpenAiProvider::parse(&tool);
        let tc = r.tool_call.expect("tool call parsed");
        assert_eq!(tc.name, "list_buckets");
        assert_eq!(tc.args["scope"], "all");
    }

    #[test]
    fn anthropic_body_has_system_top_level() {
        let p = AnthropicProvider::new("sk", "claude-3-5");
        let b = p.build_body(&req());
        assert_eq!(b["system"], "sys");
        assert_eq!(b["messages"][0]["role"], "user");
    }

    #[test]
    fn anthropic_parse_text_and_tool_use() {
        let text = json!({ "content": [ { "type": "text", "text": "done" } ] });
        assert_eq!(AnthropicProvider::parse(&text).content, "done");

        let tool = json!({ "content": [
            { "type": "text", "text": "investigating" },
            { "type": "tool_use", "name": "describe_asset", "input": { "id": "ec2-1" } }
        ] });
        let r = AnthropicProvider::parse(&tool);
        assert_eq!(r.content, "investigating");
        let tc = r.tool_call.expect("tool_use parsed");
        assert_eq!(tc.name, "describe_asset");
        assert_eq!(tc.args["id"], "ec2-1");
    }
}
