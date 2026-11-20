// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

//! Explicit signer mapping: every signer KMS key is pinned to one EntryPoint and one
//! funding group.
//!
//! The mapping file is a flat JSON array with one entry per signer key:
//!
//! ```json
//! [
//!   { "address": "0x7E5F…", "kmsKeyId": "…", "entryPoint": "v0.7", "fundingGroup": "a" }
//! ]
//! ```
//!
//! - `fundingGroup` `a`, `b` and `c` are the 1st, 2nd and 3rd funding key in
//!   `SIGNER_AWS_KMS_KEY_IDS`, the same positional rule the legacy layout uses to pair
//!   key chunks with funding keys.
//! - Order is file order: a pod that holds a funding group registers the first `N` entries
//!   for each `(entryPoint, fundingGroup)`, where `N` comes from the signer counts.
//! - Changes to the file are append-only, so the first `N` keys of a group never change
//!   while its count stays the same.

use std::{collections::HashSet, fmt, str::FromStr};

use alloy_primitives::Address;
use rundler_types::EntryPointVersion;
use serde::Deserialize;

/// Number of funding groups (and funding keys) a mapping uses.
pub const FUNDING_GROUP_COUNT: usize = 3;

/// Errors produced while parsing or validating a signer mapping or signer counts.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MappingError {
    /// The mapping contains no signers.
    #[error("signer mapping is empty")]
    Empty,
    /// An entry names an EntryPoint version rundler does not know.
    #[error("unknown entry point version {0:?}")]
    UnknownEntryPoint(String),
    /// An entry names a funding group other than `a`, `b` or `c`.
    #[error("unknown funding group {0:?}, expected one of a, b, c")]
    UnknownFundingGroup(String),
    /// Two entries share an address.
    #[error("duplicate signer address {0}")]
    DuplicateAddress(Address),
    /// Two entries share a KMS key ID.
    #[error("duplicate signer KMS key id {0}")]
    DuplicateKmsKeyId(String),
    /// The funding groups of an EntryPoint don't all have the same number of keys.
    #[error(
        "entry point {entry_point} has unbalanced funding groups (a: {a}, b: {b}, c: {c}); every group needs the same number of keys"
    )]
    UnbalancedGroups {
        /// EntryPoint version
        entry_point: String,
        /// Keys in group a
        a: usize,
        /// Keys in group b
        b: usize,
        /// Keys in group c
        c: usize,
    },
    /// The wrong number of funding key IDs was configured.
    #[error("expected {FUNDING_GROUP_COUNT} funding key ids, found {0}")]
    FundingKeyCount(usize),
    /// A funding key ID is configured twice.
    #[error("duplicate funding key id {0}")]
    DuplicateFundingKey(String),
    /// A signer key is also configured as a funding key.
    #[error("signer KMS key id {0} is also a funding key")]
    SignerIsFundingKey(String),
    /// An enabled EntryPoint has no signer count.
    #[error("entry point {0} is enabled but has no signer count")]
    MissingCount(String),
    /// A signer count is set for an EntryPoint that is not enabled.
    #[error("signer count set for entry point {0}, which is not enabled")]
    CountForDisabledEntryPoint(String),
    /// A signer count asks for more keys than a funding group has.
    #[error(
        "entry point {entry_point} asks for {requested} signers per funding group, but the mapping has {available}"
    )]
    NotEnoughKeys {
        /// EntryPoint version
        entry_point: String,
        /// Requested signers per group
        requested: usize,
        /// Keys available per group
        available: usize,
    },
    /// The signer counts string could not be parsed.
    #[error("invalid signer counts {0:?}: {1}")]
    InvalidCounts(String, String),
    /// The mapping JSON could not be parsed.
    #[error("invalid signer mapping json: {0}")]
    Json(String),
}

/// One of the funding groups a pod can lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FundingGroup {
    /// The 1st funding key
    A,
    /// The 2nd funding key
    B,
    /// The 3rd funding key
    C,
}

impl FundingGroup {
    /// All funding groups, in funding key order.
    pub const ALL: [FundingGroup; FUNDING_GROUP_COUNT] =
        [FundingGroup::A, FundingGroup::B, FundingGroup::C];

    /// Position of this group's funding key in `SIGNER_AWS_KMS_KEY_IDS`.
    pub fn index(self) -> usize {
        match self {
            FundingGroup::A => 0,
            FundingGroup::B => 1,
            FundingGroup::C => 2,
        }
    }

    /// The group whose funding key sits at `index` in `SIGNER_AWS_KMS_KEY_IDS`.
    pub fn from_index(index: usize) -> Option<FundingGroup> {
        FundingGroup::ALL.get(index).copied()
    }

    /// The group bound to `funding_key_id`, by its position in `funding_key_ids`.
    pub fn for_funding_key(
        funding_key_ids: &[String],
        funding_key_id: &str,
    ) -> Option<FundingGroup> {
        funding_key_ids
            .iter()
            .position(|id| id == funding_key_id)
            .and_then(FundingGroup::from_index)
    }
}

impl fmt::Display for FundingGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            FundingGroup::A => "a",
            FundingGroup::B => "b",
            FundingGroup::C => "c",
        };
        f.write_str(name)
    }
}

impl FromStr for FundingGroup {
    type Err = MappingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "a" => Ok(FundingGroup::A),
            "b" => Ok(FundingGroup::B),
            "c" => Ok(FundingGroup::C),
            other => Err(MappingError::UnknownFundingGroup(other.to_string())),
        }
    }
}

/// One signer key from the mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedSigner {
    /// Address of the key, as written in the mapping
    pub address: Address,
    /// KMS key ID
    pub kms_key_id: String,
    /// The only EntryPoint this key may send bundles to
    pub entry_point: EntryPointVersion,
    /// The funding group this key belongs to
    pub group: FundingGroup,
}

/// One entry exactly as it appears in the JSON file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSignerEntry {
    address: Address,
    kms_key_id: String,
    entry_point: String,
    funding_group: String,
}

/// A parsed and statically validated signer mapping.
///
/// Any value of this type has unique addresses and KMS key IDs, known EntryPoints and
/// funding groups, and the same number of keys in each funding group of an EntryPoint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Vec<RawSignerEntry>")]
pub struct SignerMapping {
    signers: Vec<MappedSigner>,
}

impl TryFrom<Vec<RawSignerEntry>> for SignerMapping {
    type Error = MappingError;

    fn try_from(raw: Vec<RawSignerEntry>) -> Result<Self, Self::Error> {
        let signers = raw
            .into_iter()
            .map(|entry| {
                Ok(MappedSigner {
                    address: entry.address,
                    kms_key_id: entry.kms_key_id,
                    entry_point: parse_entry_point(&entry.entry_point)?,
                    group: FundingGroup::from_str(&entry.funding_group)?,
                })
            })
            .collect::<Result<Vec<_>, MappingError>>()?;
        SignerMapping::new(signers)
    }
}

impl SignerMapping {
    /// Build a mapping from signers in file order, validating it.
    pub fn new(signers: Vec<MappedSigner>) -> Result<Self, MappingError> {
        let mapping = SignerMapping { signers };
        mapping.validate()?;
        Ok(mapping)
    }

    /// Parse and validate a mapping from its JSON text.
    pub fn from_json_str(json: &str) -> Result<Self, MappingError> {
        serde_json::from_str(json).map_err(|e| MappingError::Json(e.to_string()))
    }

    /// All signers, in file order.
    pub fn signers(&self) -> &[MappedSigner] {
        &self.signers
    }

    /// Keys per funding group for `entry_point` (0 if the mapping has none).
    pub fn group_size(&self, entry_point: EntryPointVersion) -> usize {
        self.count(entry_point, FundingGroup::A)
    }

    fn count(&self, entry_point: EntryPointVersion, group: FundingGroup) -> usize {
        self.signers
            .iter()
            .filter(|s| s.entry_point == entry_point && s.group == group)
            .count()
    }

    fn entry_points(&self) -> Vec<EntryPointVersion> {
        let mut entry_points = Vec::new();
        for signer in &self.signers {
            if !entry_points.contains(&signer.entry_point) {
                entry_points.push(signer.entry_point);
            }
        }
        entry_points
    }

    /// Checks that only need the mapping itself.
    fn validate(&self) -> Result<(), MappingError> {
        if self.signers.is_empty() {
            return Err(MappingError::Empty);
        }

        let mut addresses = HashSet::new();
        let mut key_ids = HashSet::new();
        for signer in &self.signers {
            if !addresses.insert(signer.address) {
                return Err(MappingError::DuplicateAddress(signer.address));
            }
            if !key_ids.insert(signer.kms_key_id.as_str()) {
                return Err(MappingError::DuplicateKmsKeyId(signer.kms_key_id.clone()));
            }
        }

        for entry_point in self.entry_points() {
            let [a, b, c] = FundingGroup::ALL.map(|group| self.count(entry_point, group));
            if a != b || b != c {
                return Err(MappingError::UnbalancedGroups {
                    entry_point: entry_point_name(entry_point).to_string(),
                    a,
                    b,
                    c,
                });
            }
        }

        Ok(())
    }

    /// Checks the mapping against a pod's configuration: the funding key IDs (in
    /// `SIGNER_AWS_KMS_KEY_IDS` order), the enabled EntryPoints and the signer counts.
    pub fn validate_against(
        &self,
        enabled_entry_points: &[EntryPointVersion],
        counts: &SignerCounts,
        funding_key_ids: &[String],
    ) -> Result<(), MappingError> {
        if funding_key_ids.len() != FUNDING_GROUP_COUNT {
            return Err(MappingError::FundingKeyCount(funding_key_ids.len()));
        }
        let mut funding = HashSet::new();
        for id in funding_key_ids {
            if !funding.insert(id.as_str()) {
                return Err(MappingError::DuplicateFundingKey(id.clone()));
            }
        }
        if let Some(signer) = self
            .signers
            .iter()
            .find(|s| funding.contains(s.kms_key_id.as_str()))
        {
            return Err(MappingError::SignerIsFundingKey(signer.kms_key_id.clone()));
        }

        for &entry_point in enabled_entry_points {
            if counts.get(entry_point).is_none() {
                return Err(MappingError::MissingCount(
                    entry_point_name(entry_point).to_string(),
                ));
            }
        }
        for &(entry_point, requested) in counts.entries() {
            if !enabled_entry_points.contains(&entry_point) {
                return Err(MappingError::CountForDisabledEntryPoint(
                    entry_point_name(entry_point).to_string(),
                ));
            }
            let available = self.group_size(entry_point);
            if requested > available {
                return Err(MappingError::NotEnoughKeys {
                    entry_point: entry_point_name(entry_point).to_string(),
                    requested,
                    available,
                });
            }
        }

        Ok(())
    }

    /// The signers a pod holding `group` registers: for each EntryPoint in `counts`, the
    /// first `N` keys of that EntryPoint and group, in file order.
    pub fn select(
        &self,
        group: FundingGroup,
        counts: &SignerCounts,
    ) -> Result<Vec<MappedSigner>, MappingError> {
        let mut selected = Vec::new();
        for &(entry_point, requested) in counts.entries() {
            let keys: Vec<&MappedSigner> = self
                .signers
                .iter()
                .filter(|s| s.entry_point == entry_point && s.group == group)
                .take(requested)
                .collect();
            if keys.len() < requested {
                return Err(MappingError::NotEnoughKeys {
                    entry_point: entry_point_name(entry_point).to_string(),
                    requested,
                    available: keys.len(),
                });
            }
            selected.extend(keys.into_iter().cloned());
        }
        Ok(selected)
    }
}

/// Signers per funding group for each EntryPoint, parsed from a string such as
/// `"v0.6=6,v0.7=20,v0.8=4,v0.9=2"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignerCounts(Vec<(EntryPointVersion, usize)>);

impl SignerCounts {
    /// The count for `entry_point`, if set.
    pub fn get(&self, entry_point: EntryPointVersion) -> Option<usize> {
        self.0
            .iter()
            .find(|(ep, _)| *ep == entry_point)
            .map(|(_, count)| *count)
    }

    /// All counts, in the order they were written.
    pub fn entries(&self) -> &[(EntryPointVersion, usize)] {
        &self.0
    }

    /// Total signers a pod registers.
    pub fn total(&self) -> usize {
        self.0.iter().map(|(_, count)| count).sum()
    }
}

impl FromStr for SignerCounts {
    type Err = MappingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: String| MappingError::InvalidCounts(s.to_string(), reason);
        let mut counts: Vec<(EntryPointVersion, usize)> = Vec::new();
        for item in s.split(',').map(str::trim).filter(|item| !item.is_empty()) {
            let (name, value) = item
                .split_once('=')
                .ok_or_else(|| invalid(format!("`{item}` is not entry_point=count")))?;
            let entry_point = parse_entry_point(name.trim()).map_err(|e| invalid(e.to_string()))?;
            let count: usize = value
                .trim()
                .parse()
                .map_err(|_| invalid(format!("`{value}` is not a number")))?;
            if count == 0 {
                return Err(invalid(format!(
                    "count for {} must be at least 1; disable the entry point instead",
                    entry_point_name(entry_point)
                )));
            }
            if counts.iter().any(|(ep, _)| *ep == entry_point) {
                return Err(invalid(format!(
                    "{} appears more than once",
                    entry_point_name(entry_point)
                )));
            }
            counts.push((entry_point, count));
        }
        if counts.is_empty() {
            return Err(invalid("no counts given".to_string()));
        }
        Ok(SignerCounts(counts))
    }
}

/// Parse a mapping EntryPoint name. Only the short form (`v0.7`) is accepted.
fn parse_entry_point(name: &str) -> Result<EntryPointVersion, MappingError> {
    match name {
        "v0.6" => Ok(EntryPointVersion::V0_6),
        "v0.7" => Ok(EntryPointVersion::V0_7),
        "v0.8" => Ok(EntryPointVersion::V0_8),
        "v0.9" => Ok(EntryPointVersion::V0_9),
        other => Err(MappingError::UnknownEntryPoint(other.to_string())),
    }
}

/// The mapping name of an EntryPoint version.
pub fn entry_point_name(entry_point: EntryPointVersion) -> &'static str {
    match entry_point {
        EntryPointVersion::V0_6 => "v0.6",
        EntryPointVersion::V0_7 => "v0.7",
        EntryPointVersion::V0_8 => "v0.8",
        EntryPointVersion::V0_9 => "v0.9",
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;

    use super::*;

    /// Shared with the ws-tools generator tests: 24 keys built from private keys 1..=24,
    /// staging-mainnet layout (groups a/b/c = legacy chunks 0-7/8-15/16-23, each split
    /// v0.7, v0.6, v0.8, v0.9 repeating, so 2 keys per EntryPoint per group).
    const GOLDEN: &str = include_str!("../testdata/signer-mapping.golden.json");

    const ALL_EPS: [EntryPointVersion; 4] = [
        EntryPointVersion::V0_6,
        EntryPointVersion::V0_7,
        EntryPointVersion::V0_8,
        EntryPointVersion::V0_9,
    ];

    fn golden() -> SignerMapping {
        SignerMapping::from_json_str(GOLDEN).unwrap()
    }

    fn funding_ids() -> Vec<String> {
        vec!["fund-a".into(), "fund-b".into(), "fund-c".into()]
    }

    fn counts(s: &str) -> SignerCounts {
        s.parse().unwrap()
    }

    fn entry(address: &str, key: &str, ep: &str, group: &str) -> String {
        format!(
            r#"{{"address":"{address}","kmsKeyId":"{key}","entryPoint":"{ep}","fundingGroup":"{group}"}}"#
        )
    }

    /// One key per EntryPoint and group for the given EntryPoints, with unique values.
    fn balanced(eps: &[&str]) -> Vec<String> {
        let mut entries = Vec::new();
        let mut i = 0u64;
        for ep in eps {
            for group in ["a", "b", "c"] {
                i += 1;
                entries.push(entry(
                    &format!("0x{i:040x}"),
                    &format!("key-{i}"),
                    ep,
                    group,
                ));
            }
        }
        entries
    }

    fn parse(entries: &[String]) -> Result<SignerMapping, MappingError> {
        SignerMapping::from_json_str(&format!("[{}]", entries.join(",")))
    }

    #[test]
    fn parses_golden_fixture() {
        let mapping = golden();
        assert_eq!(mapping.signers().len(), 24);
        for ep in ALL_EPS {
            assert_eq!(mapping.group_size(ep), 2);
        }
        let first = &mapping.signers()[0];
        assert_eq!(
            first.address,
            address!("7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
        );
        assert_eq!(first.kms_key_id, "00000000-0000-4000-8000-000000000000");
        assert_eq!(first.entry_point, EntryPointVersion::V0_7);
        assert_eq!(first.group, FundingGroup::A);
    }

    #[test]
    fn rejects_unknown_field() {
        let json = r#"[{"address":"0x0000000000000000000000000000000000000001","kmsKeyId":"k","entryPoint":"v0.7","fundingGroup":"a","order":0}]"#;
        assert!(matches!(
            SignerMapping::from_json_str(json),
            Err(MappingError::Json(_))
        ));
    }

    #[test]
    fn rejects_missing_field() {
        let json = r#"[{"address":"0x0000000000000000000000000000000000000001","kmsKeyId":"k","entryPoint":"v0.7"}]"#;
        assert!(matches!(
            SignerMapping::from_json_str(json),
            Err(MappingError::Json(_))
        ));
    }

    #[test]
    fn rejects_unknown_entry_point_and_group() {
        let mut entries = balanced(&["v0.7"]);
        entries[0] = entry(
            "0x00000000000000000000000000000000000000ff",
            "x",
            "v1.0",
            "a",
        );
        let err = parse(&entries).unwrap_err();
        assert!(
            matches!(err, MappingError::Json(msg) if msg.contains("unknown entry point version"))
        );

        let mut entries = balanced(&["v0.7"]);
        entries[0] = entry(
            "0x00000000000000000000000000000000000000ff",
            "x",
            "v0.7",
            "d",
        );
        let err = parse(&entries).unwrap_err();
        assert!(matches!(err, MappingError::Json(msg) if msg.contains("unknown funding group")));
    }

    #[test]
    fn rejects_long_entry_point_form() {
        // The CLI accepts "v0.7.0", the mapping only the short form.
        let mut entries = balanced(&["v0.7"]);
        entries[0] = entry(
            "0x00000000000000000000000000000000000000ff",
            "x",
            "v0.7.0",
            "a",
        );
        assert!(parse(&entries).is_err());
    }

    #[test]
    fn static_validation_failures() {
        // Empty.
        let err = SignerMapping::from_json_str("[]").unwrap_err().to_string();
        assert!(err.contains("signer mapping is empty"), "{err}");

        // Duplicate address.
        let mut entries = balanced(&["v0.7"]);
        entries.push(entry(
            "0x0000000000000000000000000000000000000001",
            "other",
            "v0.6",
            "a",
        ));
        let err = parse(&entries).unwrap_err().to_string();
        assert!(err.contains("duplicate signer address"), "{err}");

        // Duplicate KMS key id.
        let mut entries = balanced(&["v0.7"]);
        entries.push(entry(
            "0x00000000000000000000000000000000000000ff",
            "key-1",
            "v0.6",
            "a",
        ));
        let err = parse(&entries).unwrap_err().to_string();
        assert!(err.contains("duplicate signer KMS key id"), "{err}");

        // Unbalanced groups (extra key in group a).
        let mut entries = balanced(&["v0.7"]);
        entries.push(entry(
            "0x00000000000000000000000000000000000000ff",
            "extra",
            "v0.7",
            "a",
        ));
        let err = parse(&entries).unwrap_err().to_string();
        assert!(
            err.contains("unbalanced funding groups (a: 2, b: 1, c: 1)"),
            "{err}"
        );

        // A group missing entirely for an EntryPoint.
        let entries: Vec<String> = balanced(&["v0.7"]).into_iter().take(2).collect();
        let err = parse(&entries).unwrap_err().to_string();
        assert!(err.contains("(a: 1, b: 1, c: 0)"), "{err}");
    }

    #[test]
    fn counts_parse() {
        let c = counts("v0.6=6,v0.7=20,v0.8=4,v0.9=2");
        assert_eq!(c.get(EntryPointVersion::V0_7), Some(20));
        assert_eq!(c.get(EntryPointVersion::V0_9), Some(2));
        assert_eq!(c.total(), 32);
        // Whitespace is allowed.
        assert_eq!(counts(" v0.7 = 3 , v0.6=1 ").total(), 4);
    }

    #[test]
    fn counts_reject_bad_input() {
        for bad in [
            "",
            "v0.7=0",
            "v0.7=1,v0.7=2",
            "v0.10=1",
            "v0.7",
            "v0.7=x",
            "v0.7=-1",
        ] {
            assert!(
                matches!(
                    bad.parse::<SignerCounts>(),
                    Err(MappingError::InvalidCounts(..))
                ),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn validate_against_accepts_matching_config() {
        golden()
            .validate_against(
                &ALL_EPS,
                &counts("v0.6=2,v0.7=2,v0.8=1,v0.9=1"),
                &funding_ids(),
            )
            .unwrap();
    }

    #[test]
    fn validate_against_failures() {
        let mapping = golden();
        let all = counts("v0.6=1,v0.7=1,v0.8=1,v0.9=1");

        assert_eq!(
            mapping.validate_against(&ALL_EPS, &all, &funding_ids()[..2]),
            Err(MappingError::FundingKeyCount(2))
        );
        assert_eq!(
            mapping.validate_against(
                &ALL_EPS,
                &all,
                &["f".to_string(), "f".to_string(), "g".to_string()]
            ),
            Err(MappingError::DuplicateFundingKey("f".into()))
        );
        let signer_key = mapping.signers()[3].kms_key_id.clone();
        assert_eq!(
            mapping.validate_against(
                &ALL_EPS,
                &all,
                &["f".to_string(), signer_key.clone(), "g".to_string()]
            ),
            Err(MappingError::SignerIsFundingKey(signer_key))
        );
        assert_eq!(
            mapping.validate_against(&ALL_EPS, &counts("v0.6=1,v0.7=1,v0.8=1"), &funding_ids()),
            Err(MappingError::MissingCount("v0.9".into()))
        );
        assert_eq!(
            mapping.validate_against(
                &[EntryPointVersion::V0_7],
                &counts("v0.7=1,v0.6=1"),
                &funding_ids()
            ),
            Err(MappingError::CountForDisabledEntryPoint("v0.6".into()))
        );
        assert_eq!(
            mapping.validate_against(
                &ALL_EPS,
                &counts("v0.6=1,v0.7=3,v0.8=1,v0.9=1"),
                &funding_ids()
            ),
            Err(MappingError::NotEnoughKeys {
                entry_point: "v0.7".into(),
                requested: 3,
                available: 2
            })
        );
    }

    #[test]
    fn validate_against_entry_point_missing_from_mapping() {
        let mapping = parse(&balanced(&["v0.7"])).unwrap();
        assert_eq!(
            mapping.validate_against(
                &[EntryPointVersion::V0_7, EntryPointVersion::V0_8],
                &counts("v0.7=1,v0.8=1"),
                &funding_ids()
            ),
            Err(MappingError::NotEnoughKeys {
                entry_point: "v0.8".into(),
                requested: 1,
                available: 0
            })
        );
    }

    #[test]
    fn select_takes_first_n_in_file_order() {
        let mapping = golden();
        // Group b is legacy keys 8..=15; v0.7 keys are positions 0 and 4 in the group.
        let selected = mapping.select(FundingGroup::B, &counts("v0.7=1")).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].kms_key_id,
            "00000000-0000-4000-8000-000000000008"
        );

        let selected = mapping
            .select(FundingGroup::B, &counts("v0.7=2,v0.6=1"))
            .unwrap();
        let ids: Vec<&str> = selected.iter().map(|s| s.kms_key_id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "00000000-0000-4000-8000-000000000008",
                "00000000-0000-4000-8000-000000000012",
                "00000000-0000-4000-8000-000000000009",
            ]
        );
        assert!(selected.iter().all(|s| s.group == FundingGroup::B));
    }

    #[test]
    fn select_full_group_and_too_many() {
        let mapping = golden();
        let selected = mapping
            .select(FundingGroup::C, &counts("v0.6=2,v0.7=2,v0.8=2,v0.9=2"))
            .unwrap();
        assert_eq!(selected.len(), 8);
        assert_eq!(
            mapping.select(FundingGroup::C, &counts("v0.7=3")),
            Err(MappingError::NotEnoughKeys {
                entry_point: "v0.7".into(),
                requested: 3,
                available: 2
            })
        );
    }

    #[test]
    fn selections_of_different_groups_never_overlap() {
        let mapping = golden();
        for v6 in 1..=2 {
            for v7 in 1..=2 {
                for v8 in 1..=2 {
                    for v9 in 1..=2 {
                        let c = counts(&format!("v0.6={v6},v0.7={v7},v0.8={v8},v0.9={v9}"));
                        let picks: Vec<HashSet<Address>> = FundingGroup::ALL
                            .iter()
                            .map(|&g| {
                                mapping
                                    .select(g, &c)
                                    .unwrap()
                                    .into_iter()
                                    .map(|s| s.address)
                                    .collect()
                            })
                            .collect();
                        for i in 0..picks.len() {
                            for j in (i + 1)..picks.len() {
                                assert!(picks[i].is_disjoint(&picks[j]));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn select_is_deterministic_and_keeps_entry_points() {
        let mapping = golden();
        let c = counts("v0.6=2,v0.7=2,v0.8=1,v0.9=1");
        let first = mapping.select(FundingGroup::A, &c).unwrap();
        assert_eq!(first, mapping.select(FundingGroup::A, &c).unwrap());
        for (ep, n) in c.entries() {
            assert_eq!(first.iter().filter(|s| s.entry_point == *ep).count(), *n);
        }
    }

    #[test]
    fn appending_keys_does_not_change_selection() {
        let base = balanced(&["v0.7"]);
        let before = parse(&base).unwrap();
        let mut appended = base.clone();
        appended.extend([
            entry(
                "0x00000000000000000000000000000000000000a1",
                "new-a",
                "v0.7",
                "a",
            ),
            entry(
                "0x00000000000000000000000000000000000000b1",
                "new-b",
                "v0.7",
                "b",
            ),
            entry(
                "0x00000000000000000000000000000000000000c1",
                "new-c",
                "v0.7",
                "c",
            ),
        ]);
        let after = parse(&appended).unwrap();
        let c = counts("v0.7=1");
        for group in FundingGroup::ALL {
            assert_eq!(before.select(group, &c), after.select(group, &c));
        }
    }

    #[test]
    fn funding_group_binding_is_positional() {
        let ids = funding_ids();
        assert_eq!(
            FundingGroup::for_funding_key(&ids, "fund-a"),
            Some(FundingGroup::A)
        );
        assert_eq!(
            FundingGroup::for_funding_key(&ids, "fund-c"),
            Some(FundingGroup::C)
        );
        assert_eq!(FundingGroup::for_funding_key(&ids, "other"), None);
        assert_eq!(FundingGroup::from_index(3), None);
        assert_eq!(FundingGroup::B.to_string(), "b");
    }
}
