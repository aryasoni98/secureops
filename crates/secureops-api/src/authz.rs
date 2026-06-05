//! **Cedar authorization** (PRODUCT.md Phase 5 LAW ⑥: "Cedar feature-gate every
//! tier-locked capability").
//!
//! Every tier-locked endpoint asks [`PolicyEngine::allows`] before doing work.
//! The principal carries its license `features` as a Cedar set attribute;
//! feature-gated `permit` policies fire only when the matching feature is
//! present, and Cedar's default-deny does the rest (a Community license without
//! `bughunt` → `Decision::Deny` → `403`).

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityUid, PolicySet, Request,
    RestrictedExpression,
};

/// Built-in policy set. Feature-gated capabilities require the matching feature;
/// baseline capabilities are open to any authenticated principal.
const DEFAULT_POLICY: &str = r#"
permit(principal, action == Action::"bughunt", resource)
when { principal has features && principal.features.contains("bughunt") };

permit(principal, action == Action::"sso", resource)
when { principal has features && principal.features.contains("sso") };

permit(principal, action == Action::"threat_intel", resource)
when { principal has features && principal.features.contains("threat_intel") };

permit(principal, action == Action::"scans", resource);
permit(principal, action == Action::"findings", resource);
permit(principal, action == Action::"license", resource);
permit(principal, action == Action::"compliance", resource);
permit(principal, action == Action::"clouds", resource);
permit(principal, action == Action::"llm_keys", resource);
"#;

/// Wraps a parsed Cedar [`PolicySet`] + an [`Authorizer`].
pub struct PolicyEngine {
    policies: PolicySet,
    authorizer: Authorizer,
}

impl PolicyEngine {
    /// Build from Cedar policy source.
    pub fn new(src: &str) -> anyhow::Result<Self> {
        let policies = PolicySet::from_str(src).map_err(|e| anyhow::anyhow!("cedar parse: {e}"))?;
        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// Build the engine from the built-in [`DEFAULT_POLICY`].
    pub fn default_engine() -> Self {
        Self::new(DEFAULT_POLICY).expect("built-in Cedar policy parses")
    }

    /// `true` iff a principal holding `features` may perform `action`.
    pub fn allows(&self, features: &[String], action: &str) -> bool {
        matches!(self.evaluate(features, action), Ok(Decision::Allow))
    }

    fn evaluate(&self, features: &[String], action: &str) -> anyhow::Result<Decision> {
        let principal_uid = EntityUid::from_str("User::\"u\"")
            .map_err(|e| anyhow::anyhow!("principal uid: {e}"))?;
        let action_uid = EntityUid::from_str(&format!("Action::\"{action}\""))
            .map_err(|e| anyhow::anyhow!("action uid: {e}"))?;
        let resource_uid = EntityUid::from_str("Capability::\"c\"")
            .map_err(|e| anyhow::anyhow!("resource uid: {e}"))?;

        let feature_set = RestrictedExpression::new_set(
            features
                .iter()
                .cloned()
                .map(RestrictedExpression::new_string),
        );
        let mut attrs = HashMap::new();
        attrs.insert("features".to_string(), feature_set);
        let principal = Entity::new(principal_uid.clone(), attrs, HashSet::new())
            .map_err(|e| anyhow::anyhow!("principal entity: {e}"))?;
        let entities = Entities::from_entities([principal], None)
            .map_err(|e| anyhow::anyhow!("entities: {e}"))?;

        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            Context::empty(),
            None,
        )
        .map_err(|e| anyhow::anyhow!("cedar request: {e}"))?;

        Ok(self
            .authorizer
            .is_authorized(&request, &self.policies, &entities)
            .decision())
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::default_engine()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn community_without_feature_is_denied_bughunt() {
        let e = PolicyEngine::default();
        assert!(!e.allows(&[], "bughunt"));
        assert!(!e.allows(&["scans".to_string()], "bughunt"));
    }

    #[test]
    fn principal_with_feature_is_allowed_bughunt() {
        let e = PolicyEngine::default();
        assert!(e.allows(&["bughunt".to_string()], "bughunt"));
    }

    #[test]
    fn baseline_capabilities_open_to_all() {
        let e = PolicyEngine::default();
        assert!(e.allows(&[], "findings"));
        assert!(e.allows(&[], "scans"));
        assert!(e.allows(&[], "license"));
    }

    #[test]
    fn sso_and_threat_intel_are_gated() {
        let e = PolicyEngine::default();
        assert!(!e.allows(&[], "sso"));
        assert!(e.allows(&["sso".to_string()], "sso"));
        assert!(!e.allows(&[], "threat_intel"));
        assert!(e.allows(&["threat_intel".to_string()], "threat_intel"));
    }
}
