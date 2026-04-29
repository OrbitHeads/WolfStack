// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Threat-intel hooks for WolfRouter's `build_ruleset`.
//!
//! Returns iptables-restore lines that:
//! 1. Declare the `WOLFSTACK_THREAT_INTEL` chain.
//! 2. Match against the ipset and DROP.
//! 3. Inject a jump from `WOLFROUTER_IN` and `WOLFROUTER_FWD`.
//!
//! When threat-intel is disabled or in dry-run mode, returns an empty
//! string — the chain isn't declared, no jump exists, no kernel-level
//! filtering happens.

/// Lines to inject into WolfRouter's iptables-save-format ruleset for
/// IPv4. Empty when disabled or dry-run. Append the result inside the
/// `*filter` section, after WOLFROUTER_IN/FWD/OUT are declared but
/// before the `COMMIT` line.
pub fn iptables_lines_v4() -> String {
    let cfg = super::ThreatIntelConfig::load();
    if !super::enforcement_active(&cfg) {
        return String::new();
    }
    let mut out = String::new();
    out.push_str(":");
    out.push_str(super::CHAIN_NAME);
    out.push_str(" - [0:0]\n");
    out.push_str("-A ");
    out.push_str(super::CHAIN_NAME);
    out.push_str(" -m set --match-set ");
    out.push_str(super::IPSET_NAME_V4);
    out.push_str(" src -j DROP\n");
    out.push_str("-A WOLFROUTER_IN -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out.push_str("-A WOLFROUTER_FWD -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out
}

/// Same for ip6tables. WolfRouter's current build_ruleset is IPv4-only,
/// but we expose this for when v6 lands. Empty when disabled or dry-run.
#[allow(dead_code)]
pub fn ip6tables_lines() -> String {
    let cfg = super::ThreatIntelConfig::load();
    if !super::enforcement_active(&cfg) {
        return String::new();
    }
    let mut out = String::new();
    out.push_str(":");
    out.push_str(super::CHAIN_NAME);
    out.push_str(" - [0:0]\n");
    out.push_str("-A ");
    out.push_str(super::CHAIN_NAME);
    out.push_str(" -m set --match-set ");
    out.push_str(super::IPSET_NAME_V6);
    out.push_str(" src -j DROP\n");
    out.push_str("-A WOLFROUTER_IN -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out.push_str("-A WOLFROUTER_FWD -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_emits_nothing() {
        // Default config is disabled — should produce empty.
        let cfg = super::super::ThreatIntelConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.dry_run);
        // We can't easily mock disk loads in tests, so this is a sanity
        // check on the default — the actual function reads from disk
        // but with a default state on disk the result must be empty.
        let _ = iptables_lines_v4();  // should not panic
    }

    #[test]
    fn test_chain_name_constant() {
        assert_eq!(super::super::CHAIN_NAME, "WOLFSTACK_THREAT_INTEL");
        assert_eq!(super::super::IPSET_NAME_V4, "wolfstack-threat-intel");
        assert_eq!(super::super::IPSET_NAME_V6, "wolfstack-threat-intel-6");
    }
}
