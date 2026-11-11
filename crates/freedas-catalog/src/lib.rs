//! Model catalog with pricing, capabilities, and quality priors.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub provider: String,
    /// Bare model id; never contains '/' (provider/id joins happen in
    /// [`full_id`]), so `full_id` always splits unambiguously on the first '/'.
    pub id: String,
    pub name: String,
    pub context: u64,
    pub max_output: u64,
    pub cost_input: f64,  // per 1M tokens
    pub cost_output: f64, // per 1M tokens
    pub cost_cache_read: f64,
    #[serde(default)]
    pub cost_cache_write: f64,
    pub tools: bool,
    pub reasoning: bool,
    pub vision: bool,
    pub quality: f32, // 0..1 prior
    pub tier: String, // free|cheap|mid|frontier
    pub variants: Vec<String>,
}

impl ModelInfo {
    pub fn full_id(&self) -> String {
        format!("{}/{}", self.provider, self.id)
    }

    /// Eligible for automatic routing: tool-capable and not a client-locked
    /// free tier. Pins may still name a non-routable model explicitly.
    pub fn routable(&self) -> bool {
        self.tools && self.tier != "free"
    }

    /// The one cache-aware billed-cost function shared by gateway ledgers,
    /// provider usage events, and router reservations.
    pub fn usage_cost(&self, input: u64, cache_read: u64, cache_write: u64, output: u64) -> f64 {
        let cached = cache_read.min(input);
        let fresh = input.saturating_sub(cached);
        (fresh as f64 * self.cost_input
            + cached as f64 * self.cost_cache_read
            + cache_write as f64 * self.cost_cache_write
            + output as f64 * self.cost_output)
            / 1e6
    }

    /// Worst-case reservation for `input`/`output` with `cached`/`written`
    /// tokens already known, else 0: fresh input prices the whole prompt.
    pub fn estimate_cost(&self, input: u64, output: u64) -> f64 {
        self.usage_cost(input, 0, 0, output)
    }

    /// Consistency gate for the const catalog and any future override loader:
    /// ids stay pin-compatible, prices are finite and non-negative, quality is
    /// a 0..1 prior, and limits are non-zero.
    pub fn validate(&self) -> Result<(), String> {
        if self.provider.is_empty() || self.provider.contains('/') {
            return Err(format!("bad provider {:?}", self.provider));
        }
        if self.id.is_empty() || self.id.contains('/') {
            return Err(format!("bad id {:?}", self.id));
        }
        for (name, v) in [
            ("cost_input", self.cost_input),
            ("cost_output", self.cost_output),
            ("cost_cache_read", self.cost_cache_read),
            ("cost_cache_write", self.cost_cache_write),
        ] {
            if !v.is_finite() || v < 0.0 {
                return Err(format!("{name} must be finite and >= 0, got {v}"));
            }
        }
        if !(0.0..=1.0).contains(&self.quality) || !self.quality.is_finite() {
            return Err(format!("quality must be in 0..=1, got {}", self.quality));
        }
        if self.context == 0 || self.max_output == 0 {
            return Err("context and max_output must be non-zero".into());
        }
        if !["free", "cheap", "mid", "frontier"].contains(&self.tier.as_str()) {
            return Err(format!("bad tier {:?}", self.tier));
        }
        Ok(())
    }
}

pub fn builtin_catalog() -> Vec<ModelInfo> {
    vec![
        // Cheap tier
        mk(
            "deepseek",
            "deepseek-chat",
            "DeepSeek Chat",
            128_000,
            8_000,
            0.27,
            1.1,
            0.85,
        ),
        mk(
            "openrouter",
            // Bare id: upstream name is `deepseek/deepseek-chat`, flattened so
            // `full_id()` keeps the one-slash provider/id contract.
            "deepseek-chat",
            "DeepSeek via OpenRouter",
            128_000,
            8_000,
            0.27,
            1.1,
            0.85,
        ),
        mk(
            "openai",
            "gpt-4o-mini",
            "GPT-4o Mini",
            128_000,
            16_000,
            0.15,
            0.6,
            0.80,
        ),
        mk(
            "google",
            "gemini-2.0-flash",
            "Gemini 2.0 Flash",
            1_000_000,
            8_000,
            0.10,
            0.40,
            0.82,
        ),
        // Mid tier
        mk(
            "anthropic",
            "claude-sonnet-4-5",
            "Claude Sonnet 4.5",
            200_000,
            64_000,
            3.0,
            15.0,
            0.90,
        ),
        mk(
            "openai", "gpt-4o", "GPT-4o", 128_000, 16_000, 2.5, 10.0, 0.88,
        ),
        mk(
            "google",
            "gemini-2.0-pro",
            "Gemini 2.0 Pro",
            1_000_000,
            64_000,
            1.25,
            5.0,
            0.89,
        ),
        // Frontier tier
        mk(
            "anthropic",
            "claude-opus-4-1",
            "Claude Opus 4.1",
            200_000,
            32_000,
            15.0,
            75.0,
            0.95,
        ),
        mk(
            "openai",
            "o1",
            "OpenAI o1",
            200_000,
            100_000,
            15.0,
            60.0,
            0.94,
        ),
        // Meta Model API (api.meta.ai/v1). Costs from models.dev; quality is
        // a placeholder prior (no public benchmark data yet).
        ModelInfo {
            provider: "meta".into(),
            id: "muse-spark-1.3-contributor".into(),
            name: "Muse Spark 1.3".into(),
            context: 1_048_576,
            max_output: 131_072,
            cost_input: 0.10,
            cost_output: 0.20,
            cost_cache_read: 0.002,
            cost_cache_write: 0.125,
            tools: true,
            reasoning: true,
            vision: true,
            quality: 0.85,
            tier: "cheap".into(),
            variants: vec!["low".into(), "medium".into(), "high".into(), "max".into()],
        },
    ]
    .into_iter()
    .chain(opencode_catalog())
    .inspect(|m| debug_assert!(m.validate().is_ok(), "{}", m.full_id()))
    .collect()
}

#[allow(clippy::too_many_arguments)]
fn mk(
    provider: &str,
    id: &str,
    name: &str,
    context: u64,
    max_output: u64,
    cost_input: f64,
    cost_output: f64,
    quality: f32,
) -> ModelInfo {
    let tier = if cost_output <= 1.0 {
        "cheap"
    } else if cost_output <= 20.0 {
        "mid"
    } else {
        "frontier"
    };
    let reasoning = tier != "cheap";
    ModelInfo {
        provider: provider.into(),
        id: id.into(),
        name: name.into(),
        context,
        max_output,
        cost_input,
        cost_output,
        cost_cache_read: cost_input * 0.1,
        // No published write price for the hand-listed models; billing a cache
        // write at the fresh-input rate is the documented provider floor.
        cost_cache_write: cost_input,
        tools: true,
        reasoning,
        vision: true,
        quality,
        tier: tier.into(),
        // Cheap non-reasoning models take no variant; mirrors opencode_catalog.
        variants: if reasoning {
            vec!["low".into(), "medium".into(), "high".into(), "max".into()]
        } else {
            Vec::new()
        },
    }
}

/// OpenCode Console / Go models, priced from https://opencode.ai/docs/console/models
/// (pay-as-you-go, per 1M tokens; snapshot `PRICING_AS_OF` — refresh the table
/// against the docs page when bumping). Jev is a separate SystemOne protocol
/// and is not reachable through a chat-completions client, so it is not listed.
///
/// Tuple fields: (id, name, cost_input, cost_output, cost_cache_read,
/// cost_cache_write).
pub const PRICING_AS_OF: &str = "2026-11-11";
const OPENCODE_MODELS: &[(&str, &str, f64, f64, f64, f64)] = &[
    ("gpt-6-astra", "GPT 6 Astra", 10.0, 50.0, 1.0, 12.5),
    ("gpt-6-sol", "GPT 6 Sol", 2.0, 10.0, 0.2, 2.5),
    ("gpt-6.1-sol", "GPT 6.1 Sol", 2.0, 10.0, 0.1, 2.5),
    ("gpt-6-luna", "GPT 6 Luna", 0.1, 0.5, 0.01, 0.125),
    ("gpt-5.6-sol", "GPT 5.6 Sol", 4.0, 20.0, 0.4, 5.0),
    ("gpt-5.6-terra", "GPT 5.6 Terra", 2.0, 12.0, 0.2, 2.5),
    ("gpt-5.6-luna", "GPT 5.6 Luna", 0.2, 1.2, 0.02, 0.25),
    ("gpt-5.5", "GPT 5.5", 5.0, 30.0, 0.5, 0.0),
    ("gpt-5.5-pro", "GPT 5.5 Pro", 30.0, 180.0, 30.0, 0.0),
    ("gpt-5.4", "GPT 5.4", 2.5, 15.0, 0.25, 0.0),
    ("gpt-5.4-pro", "GPT 5.4 Pro", 30.0, 180.0, 30.0, 0.0),
    ("gpt-5.4-mini", "GPT 5.4 Mini", 0.75, 4.5, 0.075, 0.0),
    ("gpt-5.4-nano", "GPT 5.4 Nano", 0.2, 1.25, 0.02, 0.0),
    ("gpt-5.3-codex", "GPT 5.3 Codex", 1.75, 14.0, 0.175, 0.0),
    (
        "gpt-5.3-codex-spark",
        "GPT 5.3 Codex Spark",
        1.75,
        14.0,
        0.175,
        0.0,
    ),
    ("gpt-5.2", "GPT 5.2", 1.75, 14.0, 0.175, 0.0),
    ("gpt-5.2-codex", "GPT 5.2 Codex", 1.75, 14.0, 0.175, 0.0),
    ("gpt-5.1", "GPT 5.1", 1.07, 8.5, 0.107, 0.0),
    ("gpt-5.1-codex", "GPT 5.1 Codex", 1.07, 8.5, 0.107, 0.0),
    (
        "gpt-5.1-codex-max",
        "GPT 5.1 Codex Max",
        1.25,
        10.0,
        0.125,
        0.0,
    ),
    (
        "gpt-5.1-codex-mini",
        "GPT 5.1 Codex Mini",
        0.25,
        2.0,
        0.025,
        0.0,
    ),
    ("gpt-5", "GPT 5", 1.07, 8.5, 0.107, 0.0),
    ("gpt-5-codex", "GPT 5 Codex", 1.07, 8.5, 0.107, 0.0),
    ("gpt-5-nano", "GPT 5 Nano", 0.05, 0.4, 0.005, 0.0),
    ("claude-fable-5-2", "Claude Fable 5.2", 8.0, 40.0, 0.2, 10.0),
    (
        "claude-fable-5-1",
        "Claude Fable 5.1",
        10.0,
        50.0,
        0.25,
        12.5,
    ),
    ("claude-fable-5", "Claude Fable 5", 10.0, 50.0, 1.0, 12.5),
    ("claude-opus-5-5", "Claude Opus 5.5", 4.0, 20.0, 0.2, 5.0),
    ("claude-opus-5", "Claude Opus 5", 5.0, 25.0, 0.5, 6.25),
    ("claude-opus-4-8", "Claude Opus 4.8", 5.0, 25.0, 0.5, 6.25),
    ("claude-opus-4-7", "Claude Opus 4.7", 5.0, 25.0, 0.5, 6.25),
    ("claude-opus-4-6", "Claude Opus 4.6", 5.0, 25.0, 0.5, 6.25),
    ("claude-opus-4-5", "Claude Opus 4.5", 5.0, 25.0, 0.5, 6.25),
    (
        "claude-sonnet-5-5",
        "Claude Sonnet 5.5",
        2.0,
        10.0,
        0.1,
        2.5,
    ),
    ("claude-sonnet-5", "Claude Sonnet 5", 2.0, 10.0, 0.2, 2.5),
    (
        "claude-sonnet-4-6",
        "Claude Sonnet 4.6",
        3.0,
        15.0,
        0.3,
        3.75,
    ),
    (
        "claude-sonnet-4-5",
        "Claude Sonnet 4.5",
        3.0,
        15.0,
        0.3,
        3.75,
    ),
    (
        "claude-haiku-5-5",
        "Claude Haiku 5.5",
        0.1,
        0.5,
        0.01,
        0.125,
    ),
    ("claude-haiku-4-5", "Claude Haiku 4.5", 1.0, 5.0, 0.1, 1.25),
    ("gemini-4-argon", "Gemini 4 Argon", 4.0, 20.0, 0.2, 0.0),
    ("gemini-3.8-flash", "Gemini 3.8 Flash", 1.5, 7.5, 0.15, 0.0),
    ("gemini-3.7-flash", "Gemini 3.7 Flash", 1.5, 7.5, 0.15, 0.0),
    ("gemini-3.6-flash", "Gemini 3.6 Flash", 1.5, 7.5, 0.15, 0.0),
    ("gemini-3.5-flash", "Gemini 3.5 Flash", 1.5, 9.0, 0.15, 0.0),
    (
        "gemini-3.5-flash-lite",
        "Gemini 3.5 Flash Lite",
        0.3,
        2.5,
        0.03,
        0.0,
    ),
    ("gemini-3.1-pro", "Gemini 3.1 Pro", 2.0, 12.0, 0.2, 0.0),
    ("gemini-3-flash", "Gemini 3 Flash", 0.5, 3.0, 0.05, 0.0),
    ("grok-4.7", "Grok 4.7", 2.0, 6.0, 0.5, 0.0),
    ("grok-4.6", "Grok 4.6", 2.0, 6.0, 0.5, 0.0),
    ("grok-4.5", "Grok 4.5", 2.0, 6.0, 0.3, 0.0),
    ("grok-build-0.1", "Grok Build 0.1", 1.0, 2.0, 0.2, 0.0),
    ("muse-ember-1.0", "Muse Ember 1.0", 0.1, 0.5, 0.004, 0.0),
    ("muse-wonder-1.0", "Muse Wonder 1.0", 4.0, 20.0, 0.2, 0.0),
    ("muse-spark-1.3", "Muse Spark 1.3", 1.25, 4.25, 0.15, 0.0),
    ("muse-spark-1.2", "Muse Spark 1.2", 1.25, 4.25, 0.15, 0.0),
    ("qwen3.8-max", "Qwen3.8 Max", 2.0, 6.0, 0.25, 2.5),
    ("qwen3.8-flash", "Qwen3.8 Flash", 0.15, 0.47, 0.016, 0.2),
    ("qwen3.6-plus", "Qwen3.6 Plus", 0.5, 3.0, 0.05, 0.625),
    ("qwen3.5-plus", "Qwen3.5 Plus", 0.2, 1.2, 0.02, 0.25),
    (
        "deepseek-v4.1-flash",
        "DeepSeek V4.1 Flash",
        0.3,
        1.2,
        0.006,
        0.0,
    ),
    ("deepseek-v4-pro", "DeepSeek V4 Pro", 1.74, 3.48, 0.145, 0.0),
    ("minimax-m3", "MiniMax M3", 0.3, 1.2, 0.06, 0.0),
    ("minimax-m2.7", "MiniMax M2.7", 0.3, 1.2, 0.06, 0.0),
    ("minimax-m2.5", "MiniMax M2.5", 0.3, 1.2, 0.06, 0.0),
    ("glm-5.3-flash", "GLM 5.3 Flash", 0.15, 0.5, 0.03, 0.0),
    ("glm-5.3", "GLM 5.3", 1.4, 4.4, 0.26, 0.0),
    ("glm-5.2", "GLM 5.2", 1.4, 4.4, 0.26, 0.0),
    ("glm-5.1", "GLM 5.1", 1.4, 4.4, 0.26, 0.0),
    ("glm-5", "GLM 5", 1.0, 3.2, 0.2, 0.0),
    ("kimi-k2.5", "Kimi K2.5", 0.6, 3.0, 0.1, 0.0),
    ("kimi-k2.6", "Kimi K2.6", 0.95, 4.0, 0.16, 0.0),
    ("kimi-k2.7-code", "Kimi K2.7 Code", 0.95, 4.0, 0.19, 0.0),
    ("kimi-k3", "Kimi K3", 3.0, 15.0, 0.3, 3.0),
    ("mistral-large-4", "Mistral Large 4", 1.36, 4.18, 0.14, 0.0),
    ("big-pickle", "Big Pickle", 0.0, 0.0, 0.0, 0.0),
    ("iceman-free", "Iceman Free", 0.0, 0.0, 0.0, 0.0),
    (
        "inkling-2-small-free",
        "Inkling 2 Small Free",
        0.0,
        0.0,
        0.0,
        0.0,
    ),
    (
        "glm-5.3-flash-free",
        "GLM-5.3-Flash Free",
        0.0,
        0.0,
        0.0,
        0.0,
    ),
    (
        "deepseek-v4.1-flash-free",
        "DeepSeek V4.1 Flash Free",
        0.0,
        0.0,
        0.0,
        0.0,
    ),
    (
        "minimax-m3.1-flash-free",
        "MiniMax M3.1 Flash Free",
        0.0,
        0.0,
        0.0,
        0.0,
    ),
    ("beam-free", "Beam Free", 0.0, 0.0, 0.0, 0.0),
    ("flint-40b-free", "Flint 40B Free", 0.0, 0.0, 0.0, 0.0),
    ("longcat-2.5-free", "LongCat 2.5 Free", 0.0, 0.0, 0.0, 0.0),
    (
        "mimo-v2.6-flash-free",
        "MiMo-V2.6-Flash Free",
        0.0,
        0.0,
        0.0,
        0.0,
    ),
    (
        "nemotron-3-ultra-free",
        "Nemotron 3 Ultra Free",
        0.0,
        0.0,
        0.0,
        0.0,
    ),
    (
        "nemotron-3.5-lightning-free",
        "Nemotron 3.5 Lightning Free",
        0.0,
        0.0,
        0.0,
        0.0,
    ),
    (
        "nemotron-3.5-super-vl-free",
        "Nemotron 3.5 Super VL Free",
        0.0,
        0.0,
        0.0,
        0.0,
    ),
];

/// Family-level context and capability metadata; the authoritative source is
/// `https://opencode.ai/inference/v1/models`. These are conservative defaults.
fn opencode_meta(id: &str) -> (u64, u64, bool, bool) {
    if id.starts_with("gpt-") {
        (272_000, 64_000, true, true)
    } else if id.starts_with("claude-") {
        (200_000, 64_000, true, true)
    } else if id.starts_with("gemini-") {
        (1_000_000, 65_536, true, true)
    } else if id.starts_with("grok-") {
        (256_000, 64_000, true, true)
    } else if id.starts_with("kimi-") {
        (256_000, 32_000, false, true)
    } else if id.starts_with("qwen") {
        (128_000, 32_000, true, true)
    } else if id.starts_with("deepseek-") || id.starts_with("glm-") {
        (128_000, 32_000, false, true)
    } else if id.starts_with("muse-") {
        (128_000, 32_000, true, true)
    } else if id.starts_with("mistral-") || id.contains("-vl") {
        (128_000, 32_000, true, false)
    } else {
        (128_000, 32_000, false, false)
    }
}

fn opencode_catalog() -> Vec<ModelInfo> {
    OPENCODE_MODELS
        .iter()
        .map(
            |(id, name, cost_input, cost_output, cost_cache_read, cost_cache_write)| {
                let (context, max_output, vision, reasoning) = opencode_meta(id);
                let quality = if *cost_output <= 1.0 {
                    0.55
                } else if *cost_output <= 5.0 {
                    0.70
                } else if *cost_output <= 15.0 {
                    0.80
                } else {
                    0.90
                };
                // Free-tier models only answer the OpenCode client, so the router
                // must not pick them for a third-party client; pinning still works.
                let tier = if *cost_input == 0.0 && *cost_output == 0.0 {
                    "free"
                } else if *cost_output <= 1.0 {
                    "cheap"
                } else if *cost_output <= 20.0 {
                    "mid"
                } else {
                    "frontier"
                };
                ModelInfo {
                    provider: "opencode-go".into(),
                    id: (*id).into(),
                    name: (*name).into(),
                    context,
                    max_output,
                    cost_input: *cost_input,
                    cost_output: *cost_output,
                    cost_cache_read: *cost_cache_read,
                    cost_cache_write: *cost_cache_write,
                    tools: true,
                    reasoning,
                    vision,
                    quality,
                    tier: tier.into(),
                    variants: if reasoning {
                        vec!["low".into(), "medium".into(), "high".into(), "max".into()]
                    } else {
                        Vec::new()
                    },
                }
            },
        )
        .collect()
}

pub fn get_model<'a>(catalog: &'a [ModelInfo], full_id: &str) -> Option<&'a ModelInfo> {
    catalog.iter().find(|m| m.full_id() == full_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencode_catalog_covers_the_console_list() {
        let c = builtin_catalog();
        let opencode: Vec<_> = c.iter().filter(|m| m.provider == "opencode-go").collect();
        assert_eq!(opencode.len(), 87);
        let flash = opencode
            .iter()
            .find(|m| m.id == "deepseek-v4.1-flash")
            .unwrap();
        assert_eq!(flash.cost_input, 0.30);
        assert_eq!(flash.cost_output, 1.20);
        assert_eq!(flash.cost_cache_read, 0.006);
        assert!(
            opencode
                .iter()
                .any(|m| m.id == "deepseek-v4.1-flash-free" && m.tier == "free")
        );
        assert!(
            opencode
                .iter()
                .any(|m| m.id == "claude-opus-5" && m.tier == "frontier")
        );
    }

    #[test]
    fn tiers_and_cost() {
        let c = builtin_catalog();
        assert!(c.iter().any(|m| m.tier == "cheap"));
        assert!(c.iter().any(|m| m.tier == "frontier"));
        let m = &c[0];
        assert!(m.estimate_cost(1_000_000, 1_000_000) > 0.0);
    }

    #[test]
    fn every_row_validates_and_ids_stay_pin_compatible() {
        for m in builtin_catalog() {
            m.validate()
                .unwrap_or_else(|e| panic!("{}: {e}", m.full_id()));
            assert_eq!(m.full_id().matches('/').count(), 1);
        }
        // Zero-priced rows are always free tier, including the non-*-free ids.
        let catalog = builtin_catalog();
        let pickle = get_model(&catalog, "opencode-go/big-pickle").unwrap();
        assert_eq!(pickle.tier, "free");
        assert!(!pickle.routable());
    }

    #[test]
    fn usage_cost_prices_cache_terms() {
        let catalog = builtin_catalog();
        let m = get_model(&catalog, "opencode-go/gpt-6-astra").unwrap();
        // 1M fresh + 1M cached-read + 1M cache-write + 1M output.
        let cost = m.usage_cost(2_000_000, 1_000_000, 1_000_000, 1_000_000);
        let expect = 10.0 + 1.0 + 12.5 + 50.0;
        assert!((cost - expect).abs() < 1e-9);
    }
}
