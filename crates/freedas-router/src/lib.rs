//! Per-step model selection: classification, difficulty scoring, and cost choice.

use std::cmp::Ordering;

use freedas_catalog::ModelInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskClass {
    Planning,
    /// `plan-quick`: same read-only job as `Planning`, cheaper tier.
    PlanningQuick,
    Explore,
    Debug,
    Refactor,
    TestWrite,
    Upgrade,
    Docs,
    Review,
    Feature,
    Edit,
}

impl TaskClass {
    fn weight(&self) -> f32 {
        match self {
            TaskClass::Planning => 35.0,
            TaskClass::PlanningQuick => 35.0,
            TaskClass::Debug => 30.0,
            TaskClass::Refactor => 25.0,
            TaskClass::Feature => 20.0,
            TaskClass::Review => 15.0,
            TaskClass::Upgrade => 15.0,
            TaskClass::TestWrite => 10.0,
            TaskClass::Edit => 5.0,
            TaskClass::Docs => 0.0,
            TaskClass::Explore => 0.0,
        }
    }
    fn floor(&self) -> f32 {
        match self {
            TaskClass::Planning => 0.90,
            TaskClass::PlanningQuick => 0.70,
            TaskClass::Debug | TaskClass::Refactor | TaskClass::Feature => 0.80,
            TaskClass::Review | TaskClass::Upgrade => 0.78,
            TaskClass::TestWrite | TaskClass::Edit => 0.72,
            TaskClass::Docs | TaskClass::Explore => 0.65,
        }
    }
    fn output_budget(&self) -> u64 {
        match self {
            TaskClass::Planning => 4000,
            TaskClass::PlanningQuick => 2000,
            TaskClass::Debug | TaskClass::Refactor | TaskClass::Feature => 3000,
            TaskClass::Review | TaskClass::Upgrade => 2000,
            TaskClass::TestWrite | TaskClass::Docs => 1500,
            TaskClass::Edit => 1200,
            TaskClass::Explore => 800,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StepContext {
    pub agent: String,
    pub turn: u32,
    pub step: u32,
    pub prompt: String,
    pub estimated_input_tokens: u64,
    pub tool_calls_so_far: u32,
    pub failures_so_far: u32,
    pub files_touched: u32,
    pub last_error: Option<String>,
    pub plan_mode: bool,
    pub review_mode: bool,
    pub pinned_model: Option<String>,
    /// Workspace balance left for this step, when the caller knows it. Selection
    /// prefers candidates the balance covers and fails when none fit.
    pub workspace_remaining_usd: Option<f64>,
    /// Operator floor from `router.quality_floor`; selection never picks below
    /// `max(class.floor(), quality_floor)`. `None` means class floors only.
    pub quality_floor: Option<f32>,
    /// Operator cap from `router.max_escalations`; `None` uses the documented
    /// default [`MAX_ESCALATIONS`].
    pub max_escalations: Option<u32>,
    /// Input tokens the caller expects to be served from cache, if it tracks
    /// them. Reservations price these at the cache-read rate instead of the
    /// fresh-input rate.
    pub estimated_cached_input: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub model: String,
    pub task_class: TaskClass,
    pub score: f32,
    pub tier: String,
    pub reason: String,
    /// Failed steps that raised the quality floor for this decision (capped at
    /// the documented default of two).
    pub escalations: u32,
    pub estimated_cost_usd: f64,
    pub effective_quality: f32,
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum RouterError {
    #[error("no usable model: configure a provider credential (freedas providers login)")]
    EmptyCatalog,
    #[error("no model in the catalog supports tools with {needed} input tokens")]
    NoModel { needed: u64 },
    #[error(
        "budget exceeded: the cheapest capable model costs ${cost:.6} but ${remaining:.6} remains"
    )]
    BudgetExceeded { cost: f64, remaining: f64 },
}

/// The documented default `router.max_escalations`.
const MAX_ESCALATIONS: u32 = 2;

/// Prompt keywords are hints, not proof: a class chosen by keyword matching
/// (rather than the caller's agent/mode signals) can lower its floor no
/// further than this. Otherwise "docs" inside a security-sensitive prompt
/// would quietly drop the selection bar to the cheapest tier.
const KEYWORD_CLASS_MIN_FLOOR: f32 = 0.70;

/// Keyword match on word boundaries so `move` does not fire on `remove`,
/// `how` on `show`, or `split` on `splitter`. Multi-word keys match as
/// phrases; both sides are already lowercased by the caller.
fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0;
    while i + n.len() <= h.len() {
        if &h[i..i + n.len()] == n
            && (i == 0 || !is_word(h[i - 1]))
            && (i + n.len() == h.len() || !is_word(h[i + n.len()]))
        {
            return true;
        }
        i += 1;
    }
    false
}

/// True when the class came from prompt/error keywords rather than explicit
/// caller signals (agent name, review mode). Keyword-derived classes get the
/// [`KEYWORD_CLASS_MIN_FLOOR`] cap so prompt content cannot steer a step into
/// the cheapest floor.
pub fn class_is_keyword_derived(ctx: &StepContext, class: TaskClass) -> bool {
    if ctx.agent == "plan" || ctx.agent == "plan-quick" || ctx.review_mode {
        return false;
    }
    !matches!(class, TaskClass::Feature | TaskClass::Edit)
}

pub fn classify(ctx: &StepContext) -> TaskClass {
    if ctx.agent == "plan" {
        return TaskClass::Planning;
    }
    if ctx.agent == "plan-quick" {
        return TaskClass::PlanningQuick;
    }
    if ctx.review_mode {
        return TaskClass::Review;
    }
    let p = ctx.prompt.to_lowercase();
    // First turn: the runner passes turn 0 when the history is just the
    // current prompt, so exploration only triggers on a fresh session.
    if ctx.turn == 0
        && [
            "tour",
            "explain",
            "what does",
            "where is",
            "walk me through",
        ]
        .iter()
        .any(|k| contains_word(&p, k))
    {
        return TaskClass::Explore;
    }
    if ctx.failures_so_far > 0
        && let Some(e) = &ctx.last_error
    {
        let e = e.to_lowercase();
        if ["test", "fail", "error", "build"]
            .iter()
            .any(|k| contains_word(&e, k))
        {
            return TaskClass::Debug;
        }
    }
    if ["refactor", "rename", "split", "move", "extract", "inline"]
        .iter()
        .any(|k| contains_word(&p, k))
    {
        return TaskClass::Refactor;
    }
    if ["add tests", "write tests", "cover", "test for"]
        .iter()
        .any(|k| contains_word(&p, k))
    {
        return TaskClass::TestWrite;
    }
    if ["upgrade", "bump", "migrate", "migration guide"]
        .iter()
        .any(|k| contains_word(&p, k))
    {
        return TaskClass::Upgrade;
    }
    if ["release notes", "changelog", "document", "docs"]
        .iter()
        .any(|k| contains_word(&p, k))
    {
        return TaskClass::Docs;
    }
    if ctx.files_touched > 3 || ctx.prompt.len() > 500 || ctx.tool_calls_so_far > 8 {
        return TaskClass::Feature;
    }
    TaskClass::Edit
}

pub fn score(ctx: &StepContext, class: TaskClass) -> f32 {
    let multi_file = if ctx.files_touched > 3 { 1.0 } else { 0.0 };
    let pl = ctx.prompt.to_lowercase();
    let ambiguity = if [
        "why",
        "how",
        "architecture",
        "design",
        "unknown",
        "investigate",
    ]
    .iter()
    .any(|k| contains_word(&pl, k))
        || (ctx.prompt.ends_with('?') && ctx.prompt.len() > 200)
    {
        1.0
    } else {
        0.0
    };
    20.0 * (1.0 + ctx.estimated_input_tokens as f32 / 8000.0).log2()
        + 12.0 * (ctx.tool_calls_so_far.min(12) as f32)
        + 10.0 * (ctx.failures_so_far.min(3) as f32)
        + 15.0 * multi_file
        + 15.0 * ambiguity
        + class.weight()
}

fn seeded_rand(session_hint: &str, step: u32) -> f32 {
    // A per-process nonce keeps the schedule deterministic for the session
    // lifetime but unpredictable from the session id alone — a public id must
    // not let an observer forecast which steps explore.
    static NONCE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let nonce = *NONCE.get_or_init(|| {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ d.as_secs().rotate_left(21))
            .unwrap_or(0x9e3779b97f4a7c15);
        t ^ (u64::from(std::process::id()) << 32)
    });
    let mut h: u64 = 0xcbf29ce484222325 ^ nonce;
    for &b in session_hint.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= step as u64;
    h = h.wrapping_mul(0x100000001b3);
    ((h % 1000) as f32) / 1000.0
}

pub fn select(
    ctx: &StepContext,
    catalog: &[ModelInfo],
    learned: &[(String, f32)],
    session_hint: &str,
) -> Result<Decision, RouterError> {
    select_with(ctx, catalog, learned, session_hint, true)
}

#[derive(Debug, Clone, Copy)]
struct Candidate<'a> {
    model: &'a ModelInfo,
    cost: f64,
    quality: f32,
}

/// Lower cost first, then higher effective quality. `total_cmp` keeps NaNs
/// ordered instead of panicking.
fn compare_candidates(a: &Candidate<'_>, b: &Candidate<'_>) -> Ordering {
    a.cost
        .total_cmp(&b.cost)
        .then_with(|| b.quality.total_cmp(&a.quality))
}

/// Learning is per (task class, model): a model that debugs well is not
/// assumed to plan well. Keys are `format!("{class:?}/{id}")`, matching the
/// `task_class` strings the session records.
fn learned_key(class: TaskClass, id: &str) -> String {
    format!("{class:?}/{id}")
}

fn effective_quality(
    model: &ModelInfo,
    learned: &[(String, f32)],
    learn: bool,
    class: TaskClass,
    id: &str,
) -> f32 {
    let quality = if learn {
        let key = learned_key(class, id);
        let learned_q = learned
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, q)| *q)
            .unwrap_or(0.5);
        0.7 * model.quality + 0.3 * learned_q
    } else {
        model.quality
    };
    // An unusable prior must not make a model look free or crash selection.
    if quality.is_finite() {
        quality.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn candidate<'a>(
    ctx: &StepContext,
    model: &'a ModelInfo,
    quality: f32,
    class: TaskClass,
) -> Candidate<'a> {
    let output = model.max_output.min(class.output_budget());
    let cost = model.usage_cost(
        ctx.estimated_input_tokens,
        ctx.estimated_cached_input,
        0,
        output,
    ) + (1.0 - quality as f64) * 0.02;
    Candidate {
        model,
        cost: if cost.is_finite() { cost } else { f64::MAX },
        quality,
    }
}

/// `learn = false` uses static quality priors only: learned outcomes are not
/// blended in and epsilon exploration is skipped, so the choice is reproducible.
pub fn select_with(
    ctx: &StepContext,
    catalog: &[ModelInfo],
    learned: &[(String, f32)],
    session_hint: &str,
    learn: bool,
) -> Result<Decision, RouterError> {
    let class = classify(ctx);
    let sc = score(ctx, class);
    // Pinned model short-circuits the auto selection. A catalog hit reports
    // the real cost and quality via `candidate` so stats and
    // `router explain` stay meaningful. An unknown id cannot be priced, so
    // with a workspace budget it fails closed (`NoModel`: spend cannot be
    // authorized); without one it passes through audited
    // (`mode: pinned-unknown`, zero cost/quality) and the provider layer
    // still fails loud on a truly unknown provider.
    if let Some(pinned) = &ctx.pinned_model {
        let Some(m) = catalog.iter().find(|m| m.full_id() == *pinned) else {
            let needed = ctx
                .estimated_input_tokens
                .saturating_add(class.output_budget());
            if ctx.workspace_remaining_usd.is_some() {
                return Err(RouterError::NoModel { needed });
            }
            return Ok(Decision {
                model: pinned.clone(),
                task_class: class,
                score: sc,
                // Unaudited: no catalog row means no price, so the spend is
                // flagged rather than recorded as $0.00.
                tier: "unaudited".into(),
                reason: "pinned-unknown".into(),
                escalations: 0,
                estimated_cost_usd: 0.0,
                effective_quality: 0.0,
                mode: "pinned-unknown".into(),
            });
        };
        // A pin is an explicit choice, but it cannot conjure capabilities:
        // no-tools or too-small context fails the step loudly instead of
        // dying later inside the provider.
        let needed = ctx
            .estimated_input_tokens
            .saturating_add(class.output_budget());
        if !m.tools || m.context < needed {
            return Err(RouterError::NoModel { needed });
        }
        let tier = m.tier.clone();
        let id = m.full_id();
        let quality = effective_quality(m, learned, learn, class, &id);
        let cost = candidate(ctx, m, quality, class).cost;
        if let Some(remaining) = ctx.workspace_remaining_usd
            && cost > remaining + 1e-9
        {
            return Err(RouterError::BudgetExceeded { cost, remaining });
        }
        return Ok(Decision {
            model: pinned.clone(),
            task_class: class,
            score: sc,
            tier,
            reason: "pinned".into(),
            escalations: 0,
            estimated_cost_usd: cost,
            effective_quality: quality,
            mode: "pinned".into(),
        });
    }
    if catalog.is_empty() {
        return Err(RouterError::EmptyCatalog);
    }

    // Reserve the class output budget on top of the input, saturating so a
    // huge estimate cannot wrap the context filter.
    let needed = ctx
        .estimated_input_tokens
        .saturating_add(class.output_budget());
    let eligible: Vec<Candidate<'_>> = catalog
        .iter()
        // Free-tier models are pinned-only: they answer a specific client.
        .filter(|m| m.routable() && m.context >= needed)
        .map(|m| {
            let quality = effective_quality(m, learned, learn, class, &m.full_id());
            candidate(ctx, m, quality, class)
        })
        .collect();
    if eligible.is_empty() {
        return Err(RouterError::NoModel { needed });
    }

    // One failure is noise; two consecutive failures escalate one tier,
    // capped by `router.max_escalations` (default MAX_ESCALATIONS).
    let max_escalations = ctx.max_escalations.unwrap_or(MAX_ESCALATIONS);
    let escalations = if ctx.failures_so_far >= 2 {
        ctx.failures_so_far.min(max_escalations)
    } else {
        0
    };
    // The effective floor never drops below the operator's `quality_floor`,
    // and keyword-derived classes never drop below KEYWORD_CLASS_MIN_FLOOR:
    // prompt text can only steer a step to a bounded-cheap class.
    let mut floor = (class.floor() + 0.05 * escalations as f32)
        .max(ctx.quality_floor.unwrap_or(0.0))
        .max(if class_is_keyword_derived(ctx, class) {
            KEYWORD_CLASS_MIN_FLOOR
        } else {
            0.0
        })
        .min(1.0);

    // Never explore or select a model the remaining balance cannot cover.
    let affordable: Vec<Candidate<'_>> = match ctx.workspace_remaining_usd {
        Some(remaining) => eligible
            .iter()
            .copied()
            .filter(|c| c.cost <= remaining + 1e-9)
            .collect(),
        None => eligible.clone(),
    };
    let pool = if affordable.is_empty() {
        &eligible
    } else {
        &affordable
    };

    // Rank the floor-filtered set so exploration below picks from the same
    // qualified models, never a capability/context/budget reject.
    let mut ranked: Vec<Candidate<'_>>;
    loop {
        ranked = pool
            .iter()
            .copied()
            .filter(|c| c.quality >= floor)
            .collect();
        ranked.sort_by(compare_candidates);
        if !ranked.is_empty() || floor <= 0.0 {
            break;
        }
        floor = (floor - 0.05).max(0.0);
    }
    let primary = ranked.first().copied().unwrap_or_else(|| {
        *pool
            .iter()
            .min_by(|a, b| compare_candidates(a, b))
            .expect("candidate pool is non-empty")
    });
    if let Some(remaining) = ctx.workspace_remaining_usd
        && primary.cost > remaining + 1e-9
    {
        return Err(RouterError::BudgetExceeded {
            cost: primary.cost,
            remaining,
        });
    }

    let mut final_choice = primary;
    // Exploration: 10% pick the runner-up from the ranked floor-filtered set.
    if learn
        && seeded_rand(session_hint, ctx.step) < 0.10
        && let Some(second) = ranked
            .iter()
            .skip(1)
            .find(|c| c.model.full_id() != primary.model.full_id())
    {
        final_choice = *second;
    }

    Ok(Decision {
        model: final_choice.model.full_id(),
        task_class: class,
        score: sc,
        tier: final_choice.model.tier.clone(),
        reason: format!(
            "class={class:?} floor={floor:.2} eff_q={:.2} escalations={escalations}",
            final_choice.quality
        ),
        escalations,
        estimated_cost_usd: final_choice.cost,
        effective_quality: final_choice.quality,
        mode: "auto".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> StepContext {
        StepContext {
            agent: "build".into(),
            turn: 1,
            step: 1,
            prompt: "Fix the test failure".into(),
            estimated_input_tokens: 4000,
            tool_calls_so_far: 2,
            failures_so_far: 1,
            files_touched: 1,
            last_error: Some("test failed".into()),
            plan_mode: false,
            review_mode: false,
            pinned_model: None,
            workspace_remaining_usd: None,
            quality_floor: None,
            max_escalations: None,
            estimated_cached_input: 0,
        }
    }

    fn model(
        id: &str,
        tools: bool,
        context: u64,
        quality: f32,
        cost_input: f64,
        cost_output: f64,
    ) -> ModelInfo {
        ModelInfo {
            provider: "test".into(),
            id: id.into(),
            name: id.into(),
            context,
            max_output: 8_000,
            cost_input,
            cost_output,
            cost_cache_read: cost_input * 0.1,
            cost_cache_write: 0.0,
            tools,
            reasoning: false,
            vision: false,
            quality,
            tier: "mid".into(),
            variants: vec![],
        }
    }

    #[test]
    fn classifies_debug() {
        assert_eq!(classify(&ctx()), TaskClass::Debug);
    }

    #[test]
    fn classify_uses_word_boundaries() {
        let mut c = ctx();
        c.failures_so_far = 0;
        c.last_error = None;
        // `move` inside `remove` is not a refactor; `explain` inside
        // `unexplained` is not an explore prompt.
        c.prompt = "remove the temp file".into();
        assert_eq!(classify(&c), TaskClass::Edit);
        c.turn = 0;
        c.prompt = "fix the unexplained failure".into();
        assert_eq!(classify(&c), TaskClass::Edit);
    }

    #[test]
    fn selects_cheap_for_edit_and_frontier_for_plan() {
        let cat = freedas_catalog::builtin_catalog();
        let mut e = ctx();
        e.prompt = "Fix a typo in the README".into();
        e.failures_so_far = 0;
        e.last_error = None;
        let d = select(&e, &cat, &[], "ses_1").unwrap();
        assert_eq!(d.task_class, TaskClass::Edit);
        assert_eq!(d.mode, "auto");
        let mut p = ctx();
        p.agent = "plan".into();
        p.prompt = "plan".into();
        let dp = select(&p, &cat, &[], "ses_1").unwrap();
        assert_eq!(dp.task_class, TaskClass::Planning);
        // Planning floor is higher => chosen model quality >= edit floor target.
        let plan_m = cat.iter().find(|m| m.full_id() == dp.model).unwrap();
        assert!(plan_m.quality >= 0.90 || dp.model.contains("opus") || dp.model.contains("o1"));
    }

    #[test]
    fn pinned_short_circuits() {
        let cat = freedas_catalog::builtin_catalog();
        let mut c = ctx();
        c.pinned_model = Some("openai/gpt-4o-mini".into());
        let d = select(&c, &cat, &[], "s").unwrap();
        assert_eq!(d.mode, "pinned");
        assert_eq!(d.model, "openai/gpt-4o-mini");
        // Known pinned id resolves the real catalog tier/cost/quality.
        let m = cat
            .iter()
            .find(|m| m.full_id() == "openai/gpt-4o-mini")
            .unwrap();
        assert_eq!(d.tier, m.tier);
        assert!(d.estimated_cost_usd > 0.0);
        assert!(d.effective_quality > 0.0);
        // Unknown pinned id passes through audited when no budget gates spend,
        // so custom-provider and fake-model pins keep working; the provider
        // layer still fails loud on a truly unknown provider.
        c.pinned_model = Some("nope/missing".into());
        c.workspace_remaining_usd = None;
        let d = select(&c, &cat, &[], "s").unwrap();
        assert_eq!(d.mode, "pinned-unknown");
        assert_eq!(d.model, "nope/missing");
        assert_eq!(d.tier, "unaudited");
        assert_eq!(d.estimated_cost_usd, 0.0);
        assert_eq!(d.effective_quality, 0.0);
        // ...but fails closed once a budget must authorize the spend.
        c.workspace_remaining_usd = Some(10.0);
        assert!(matches!(
            select(&c, &cat, &[], "s"),
            Err(RouterError::NoModel { .. })
        ));
        c.workspace_remaining_usd = None;
        assert_eq!(select(&c, &[], &[], "s").unwrap().mode, "pinned-unknown");
        // Pinned cost respects the workspace budget.
        c.pinned_model = Some("openai/gpt-4o-mini".into());
        c.workspace_remaining_usd = Some(0.0);
        assert!(matches!(
            select(&c, &cat, &[], "s"),
            Err(RouterError::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn empty_catalog_errors_instead_of_panicking() {
        let err = select(&ctx(), &[], &[], "s").unwrap_err();
        assert_eq!(err, RouterError::EmptyCatalog);
    }

    #[test]
    fn no_capable_model_errors() {
        let cat = vec![model("blind", false, 1_000_000, 0.9, 0.1, 0.1)];
        let err = select(&ctx(), &cat, &[], "s").unwrap_err();
        assert!(matches!(err, RouterError::NoModel { .. }));

        let cat = vec![model("tiny", true, 1_000, 0.9, 0.1, 0.1)];
        let err = select(&ctx(), &cat, &[], "s").unwrap_err();
        assert!(matches!(err, RouterError::NoModel { .. }));
    }

    #[test]
    fn nan_quality_does_not_panic() {
        let cat = vec![model("nan", true, 1_000_000, f32::NAN, 0.1, 0.1)];
        let d = select(&ctx(), &cat, &[], "s").unwrap();
        assert_eq!(d.model, "test/nan");
        assert!(d.effective_quality.is_finite());
        assert!(d.estimated_cost_usd.is_finite());
    }

    #[test]
    fn relaxes_the_floor_while_keeping_filters() {
        let cat = vec![model("weak", true, 1_000_000, 0.1, 0.1, 0.1)];
        let mut c = ctx();
        c.agent = "plan".into();
        let d = select_with(&c, &cat, &[], "s", false).unwrap();
        assert_eq!(d.model, "test/weak");
        assert!(d.reason.contains("floor=0.10"));
    }

    #[test]
    fn exploration_only_picks_eligible_models() {
        let cat = vec![
            // Cheapest, highest quality, but cannot call tools.
            model("ineligible", false, 1_000_000, 1.0, 0.0, 0.0),
            model("eligible-a", true, 1_000_000, 0.9, 1.0, 1.0),
            model("eligible-b", true, 1_000_000, 0.81, 0.5, 0.5),
        ];
        let mut c = ctx();
        c.prompt = "Fix a typo in the README".into();
        c.failures_so_far = 0;
        c.last_error = None;
        let base = select_with(&c, &cat, &[], "s", false).unwrap();
        let mut explored = false;
        for step in 0..200 {
            c.step = step;
            let d = select_with(&c, &cat, &[], "s", true).unwrap();
            assert_ne!(d.model, "test/ineligible", "step {step}");
            assert_eq!(d.task_class, TaskClass::Edit);
            if d.model != base.model {
                explored = true;
            }
        }
        assert!(explored, "exploration never triggered");
    }

    #[test]
    fn escalates_the_floor_on_failures() {
        let cat = freedas_catalog::builtin_catalog();
        let mut c = ctx();
        c.failures_so_far = 0;
        c.last_error = None;
        let d = select_with(&c, &cat, &[], "s", false).unwrap();
        assert_eq!(d.escalations, 0);
        // One failure is noise: no escalation.
        c.failures_so_far = 1;
        let same = select_with(&c, &cat, &[], "s", false).unwrap();
        assert_eq!(same.escalations, 0);
        c.failures_so_far = 2;
        let escalated = select_with(&c, &cat, &[], "s", false).unwrap();
        assert_eq!(escalated.escalations, 2);
        assert!(escalated.reason.contains("floor="));
        c.failures_so_far = 9;
        let capped = select_with(&c, &cat, &[], "s", false).unwrap();
        assert_eq!(capped.escalations, MAX_ESCALATIONS);
    }

    #[test]
    fn budget_filters_candidates_and_fails_when_nothing_fits() {
        let cat = vec![
            model("pricey", true, 1_000_000, 0.9, 100.0, 100.0),
            model("cheap", true, 1_000_000, 0.75, 0.0, 0.0),
        ];
        let mut c = ctx();
        c.prompt = "Fix a typo in the README".into();
        c.failures_so_far = 0;
        c.last_error = None;
        c.workspace_remaining_usd = Some(0.05);
        let d = select_with(&c, &cat, &[], "s", false).unwrap();
        assert_eq!(d.model, "test/cheap");

        c.workspace_remaining_usd = Some(0.0);
        let err = select_with(&c, &cat, &[], "s", false).unwrap_err();
        assert!(matches!(err, RouterError::BudgetExceeded { .. }));
    }

    fn tier_rank(tier: &str) -> u8 {
        match tier {
            "cheap" => 0,
            "mid" => 1,
            _ => 2,
        }
    }

    #[test]
    fn plan_quick_lands_on_a_cheaper_tier_than_plan() {
        let cat = freedas_catalog::builtin_catalog();
        let mut c = ctx();
        c.agent = "plan".into();
        c.prompt = "Plan the feature".into();
        let deep = select_with(&c, &cat, &[], "ses_1", false).unwrap();
        c.agent = "plan-quick".into();
        let quick = select_with(&c, &cat, &[], "ses_1", false).unwrap();
        assert_eq!(deep.task_class, TaskClass::Planning);
        assert_eq!(quick.task_class, TaskClass::PlanningQuick);
        assert!(
            tier_rank(&quick.tier) < tier_rank(&deep.tier),
            "quick={:?} deep={:?}",
            quick,
            deep
        );
    }

    #[test]
    fn learn_disabled_uses_static_priors_and_skips_exploration() {
        // The base catalog keeps this test independent of provider listings.
        let cat: Vec<_> = freedas_catalog::builtin_catalog()
            .into_iter()
            .filter(|m| m.provider != "opencode-go")
            .collect();
        let mut c = ctx();
        c.prompt = "Fix a typo in the README".into();
        c.failures_so_far = 0;
        c.last_error = None;
        // Priors that punish the cheap tier: blending them would move the choice.
        // Learning is keyed by (task class, model), so use the run's class.
        let learned: Vec<(String, f32)> = cat
            .iter()
            .map(|m| {
                (
                    learned_key(TaskClass::Edit, &m.full_id()),
                    if m.tier == "cheap" { 0.0 } else { 1.0 },
                )
            })
            .collect();
        let budget = TaskClass::Edit.output_budget();
        let cheapest = cat
            .iter()
            .filter(|m| m.tools)
            .min_by(|a, b| {
                let ca = a.estimate_cost(c.estimated_input_tokens, a.max_output.min(budget));
                let cb = b.estimate_cost(c.estimated_input_tokens, b.max_output.min(budget));
                ca.partial_cmp(&cb).unwrap()
            })
            .unwrap()
            .full_id();
        for step in 0..32 {
            c.step = step;
            let d = select_with(&c, &cat, &learned, "ses_1", false).unwrap();
            let model = cat.iter().find(|m| m.full_id() == d.model).unwrap();
            assert_eq!(d.model, cheapest, "step {step}");
            assert_eq!(d.effective_quality, model.quality, "step {step}");
        }
        // The same priors do change the choice while learning is on.
        let with_learning = select_with(&c, &cat, &learned, "ses_1", true).unwrap();
        assert_ne!(with_learning.model, cheapest);
        assert_ne!(with_learning.tier, "cheap");
    }
}
