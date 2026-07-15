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

use alloy_primitives::{U64, U256};
use rundler_types::{
    BundlerSponsorship, EntryPointVersion, UserOperationPermissions, chain::ChainSpec,
};
use serde::{Deserialize, Serialize};

use crate::utils::{FromRpcType, IntoRundlerType};

/// User operation permissions
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcPermissions {
    /// Whether the user operation is trusted, allowing the bundler to skip untrusted simulation
    #[serde(default)]
    pub(crate) trusted: bool,
    /// The maximum sender allowed in the pool
    #[serde(default)]
    pub(crate) max_allowed_in_pool_for_sender: Option<U64>,
    /// The allowed percentage of underpriced fees that is accepted into the pool
    #[serde(default)]
    pub(crate) underpriced_accept_pct: Option<U64>,
    /// The allowed percentage of fees underpriced that is bundled
    #[serde(default)]
    pub(crate) underpriced_bundle_pct: Option<U64>,
    /// Bundler sponsorship settings
    #[serde(default)]
    pub(crate) bundler_sponsorship: Option<RpcBundlerSponsorship>,
    /// Disable EIP-7702
    #[serde(default)]
    pub(crate) eip7702_disabled: Option<bool>,
}

/// Per-request override for the maximum block range used when looking up user operation
/// events, parsed from the [`headers::MAX_BLOCK_RANGE`] header.
///
/// Deliberately separate from [`RpcPermissions`]: this is lookup configuration, not a user
/// operation permission, and its presence must not affect the header-vs-positional
/// permissions precedence on `eth_sendUserOperation`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MaxBlockRange(pub(crate) u64);

impl MaxBlockRange {
    /// Parse the max block range override from HTTP headers, if present.
    pub(crate) fn from_headers(
        headers: &http::HeaderMap,
    ) -> Result<Option<Self>, PermissionsHeaderError> {
        Ok(header_str(headers, headers::MAX_BLOCK_RANGE)?
            .map(|s| parse_u64(headers::MAX_BLOCK_RANGE, s))
            .transpose()?
            .map(MaxBlockRange))
    }
}

/// HTTP header names carrying per-request user operation permissions.
///
/// Header lookups are case-insensitive, so these are stored lowercased.
pub(crate) mod headers {
    /// Override for the maximum block range used when looking up user operation events.
    pub(crate) const MAX_BLOCK_RANGE: &str = "x-rundler-max-block-range";
    /// Whether the user operation is trusted.
    pub(crate) const TRUSTED: &str = "x-rundler-trusted";
    /// Maximum number of user operations allowed for a sender in the mempool.
    pub(crate) const MAX_OPS_IN_POOL_FOR_SENDER: &str = "x-rundler-max-ops-in-pool-for-sender";
    /// Allowed percentage of underpriced fees accepted into the pool.
    pub(crate) const UNDERPRICED_ACCEPT_PCT: &str = "x-rundler-underpriced-accept-pct";
    /// Allowed percentage of underpriced fees that is bundled.
    pub(crate) const UNDERPRICED_BUNDLE_PCT: &str = "x-rundler-underpriced-bundle-pct";
    /// Whether EIP-7702 is disabled.
    pub(crate) const EIP7702_DISABLED: &str = "x-rundler-eip7702-disabled";
    /// Maximum cost the bundler is willing to pay (U256, 0x-hex).
    pub(crate) const SPONSORSHIP_MAX_COST: &str = "x-rundler-sponsorship-max-cost";
    /// Unix timestamp (seconds) until which the sponsorship is valid.
    pub(crate) const SPONSORSHIP_VALID_UNTIL: &str = "x-rundler-sponsorship-valid-until";
}

/// Error parsing a permissions HTTP header.
#[derive(Debug, thiserror::Error)]
#[error("invalid permissions header `{header}`: {reason}")]
pub(crate) struct PermissionsHeaderError {
    pub(crate) header: &'static str,
    pub(crate) reason: String,
}

impl RpcPermissions {
    /// Parse per-request permissions from HTTP headers.
    ///
    /// Every header is optional; absent headers leave their field at the default. Returns
    /// `Ok(None)` when no permissions header is present at all (so the caller can fall back to
    /// the legacy positional parameter), `Ok(Some(_))` when at least one is present, and `Err`
    /// when a header is malformed or only one of the coupled sponsorship pair is supplied.
    pub(crate) fn from_headers(
        headers: &http::HeaderMap,
    ) -> Result<Option<Self>, PermissionsHeaderError> {
        let mut present = false;
        let mut perms = RpcPermissions::default();

        if let Some(s) = header_str(headers, headers::TRUSTED)? {
            present = true;
            perms.trusted = parse_bool(headers::TRUSTED, s)?;
        }
        if let Some(s) = header_str(headers, headers::MAX_OPS_IN_POOL_FOR_SENDER)? {
            present = true;
            perms.max_allowed_in_pool_for_sender = Some(U64::from(parse_u64(
                headers::MAX_OPS_IN_POOL_FOR_SENDER,
                s,
            )?));
        }
        if let Some(s) = header_str(headers, headers::UNDERPRICED_ACCEPT_PCT)? {
            present = true;
            perms.underpriced_accept_pct =
                Some(U64::from(parse_u64(headers::UNDERPRICED_ACCEPT_PCT, s)?));
        }
        if let Some(s) = header_str(headers, headers::UNDERPRICED_BUNDLE_PCT)? {
            present = true;
            perms.underpriced_bundle_pct =
                Some(U64::from(parse_u64(headers::UNDERPRICED_BUNDLE_PCT, s)?));
        }
        if let Some(s) = header_str(headers, headers::EIP7702_DISABLED)? {
            present = true;
            perms.eip7702_disabled = Some(parse_bool(headers::EIP7702_DISABLED, s)?);
        }

        // Sponsorship is a coupled pair: both or neither, never exactly one.
        let max_cost = header_str(headers, headers::SPONSORSHIP_MAX_COST)?;
        let valid_until = header_str(headers, headers::SPONSORSHIP_VALID_UNTIL)?;
        match (max_cost, valid_until) {
            (Some(mc), Some(vu)) => {
                present = true;
                perms.bundler_sponsorship = Some(RpcBundlerSponsorship {
                    max_cost: parse_u256_hex(headers::SPONSORSHIP_MAX_COST, mc)?,
                    valid_until: U64::from(parse_u64(headers::SPONSORSHIP_VALID_UNTIL, vu)?),
                });
            }
            (None, None) => {}
            (Some(_), None) => {
                return Err(PermissionsHeaderError {
                    header: headers::SPONSORSHIP_VALID_UNTIL,
                    reason: format!(
                        "must be set together with `{}`",
                        headers::SPONSORSHIP_MAX_COST
                    ),
                });
            }
            (None, Some(_)) => {
                return Err(PermissionsHeaderError {
                    header: headers::SPONSORSHIP_MAX_COST,
                    reason: format!(
                        "must be set together with `{}`",
                        headers::SPONSORSHIP_VALID_UNTIL
                    ),
                });
            }
        }

        Ok(present.then_some(perms))
    }
}

fn header_str<'a>(
    headers: &'a http::HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, PermissionsHeaderError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    // Fail closed on ambiguity: these headers carry policy, so a smuggled or
    // proxy-appended duplicate must not be silently first-wins.
    if values.next().is_some() {
        return Err(PermissionsHeaderError {
            header: name,
            reason: "header supplied more than once".to_string(),
        });
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| PermissionsHeaderError {
            header: name,
            reason: "value is not valid ASCII".to_string(),
        })
}

fn parse_bool(name: &'static str, s: &str) -> Result<bool, PermissionsHeaderError> {
    if s.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if s.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(PermissionsHeaderError {
            header: name,
            reason: format!("expected `true` or `false`, got `{s}`"),
        })
    }
}

fn parse_u64(name: &'static str, s: &str) -> Result<u64, PermissionsHeaderError> {
    s.trim().parse::<u64>().map_err(|e| PermissionsHeaderError {
        header: name,
        reason: format!("expected an unsigned integer: {e}"),
    })
}

fn parse_u256_hex(name: &'static str, s: &str) -> Result<U256, PermissionsHeaderError> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| PermissionsHeaderError {
            header: name,
            reason: "expected a 0x-prefixed hex string".to_string(),
        })?;
    U256::from_str_radix(stripped, 16).map_err(|e| PermissionsHeaderError {
        header: name,
        reason: format!("invalid hex value: {e}"),
    })
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcBundlerSponsorship {
    /// The maximum cost the bundler is willing to pay for the user operation
    pub(crate) max_cost: U256,
    /// The valid until timestamp of the sponsorship
    pub(crate) valid_until: U64,
}

impl FromRpcType<RpcPermissions> for UserOperationPermissions {
    fn from_rpc_type(
        rpc: RpcPermissions,
        chain_spec: &ChainSpec,
        ep_version: EntryPointVersion,
    ) -> Self {
        UserOperationPermissions {
            trusted: rpc.trusted,
            max_allowed_in_pool_for_sender: rpc.max_allowed_in_pool_for_sender.map(|c| c.to()),
            underpriced_accept_pct: rpc.underpriced_accept_pct.map(|c| c.to()),
            underpriced_bundle_pct: rpc.underpriced_bundle_pct.map(|c| c.to()),
            bundler_sponsorship: rpc
                .bundler_sponsorship
                .map(|c| c.into_rundler_type(chain_spec, ep_version)),
            eip7702_disabled: rpc.eip7702_disabled.unwrap_or(false),
        }
    }
}

impl FromRpcType<RpcBundlerSponsorship> for BundlerSponsorship {
    fn from_rpc_type(
        rpc: RpcBundlerSponsorship,
        _chain_spec: &ChainSpec,
        _ep_version: EntryPointVersion,
    ) -> Self {
        BundlerSponsorship {
            max_cost: rpc.max_cost,
            valid_until: rpc.valid_until.to(),
        }
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderName, HeaderValue};

    use super::*;

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn no_headers_returns_none() {
        let parsed = RpcPermissions::from_headers(&HeaderMap::new()).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn parses_all_scalar_headers() {
        let headers = headers_from(&[
            (headers::TRUSTED, "true"),
            (headers::MAX_OPS_IN_POOL_FOR_SENDER, "4"),
            (headers::UNDERPRICED_ACCEPT_PCT, "10"),
            (headers::UNDERPRICED_BUNDLE_PCT, "20"),
            (headers::EIP7702_DISABLED, "false"),
        ]);

        let perms = RpcPermissions::from_headers(&headers)
            .unwrap()
            .expect("at least one header present");

        assert!(perms.trusted);
        assert_eq!(perms.max_allowed_in_pool_for_sender, Some(U64::from(4)));
        assert_eq!(perms.underpriced_accept_pct, Some(U64::from(10)));
        assert_eq!(perms.underpriced_bundle_pct, Some(U64::from(20)));
        assert_eq!(perms.eip7702_disabled, Some(false));
        assert!(perms.bundler_sponsorship.is_none());
    }

    #[test]
    fn max_block_range_is_independent_of_permissions() {
        let headers = headers_from(&[(headers::MAX_BLOCK_RANGE, "1000")]);

        let range = MaxBlockRange::from_headers(&headers)
            .unwrap()
            .expect("range header present");
        assert_eq!(range.0, 1000);

        // The lookup-scoped header must not count as "permissions present", otherwise a
        // gateway attaching it would wipe out positional permissions on sends.
        assert!(RpcPermissions::from_headers(&headers).unwrap().is_none());
    }

    #[test]
    fn malformed_max_block_range_is_rejected() {
        let headers = headers_from(&[(headers::MAX_BLOCK_RANGE, "not-a-number")]);
        let err = MaxBlockRange::from_headers(&headers).unwrap_err();
        assert_eq!(err.header, headers::MAX_BLOCK_RANGE);
    }

    #[test]
    fn duplicate_header_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(headers::TRUSTED, HeaderValue::from_static("true"));
        headers.append(headers::TRUSTED, HeaderValue::from_static("false"));

        let err = RpcPermissions::from_headers(&headers).unwrap_err();
        assert_eq!(err.header, headers::TRUSTED);
    }

    #[test]
    fn parses_sponsorship_pair() {
        let headers = headers_from(&[
            (headers::SPONSORSHIP_MAX_COST, "0x1bc16d674ec80000"),
            (headers::SPONSORSHIP_VALID_UNTIL, "1893456000"),
        ]);

        let perms = RpcPermissions::from_headers(&headers)
            .unwrap()
            .expect("sponsorship present");
        let sponsorship = perms.bundler_sponsorship.expect("sponsorship parsed");
        assert_eq!(
            sponsorship.max_cost,
            U256::from(2_000_000_000_000_000_000u64)
        );
        assert_eq!(sponsorship.valid_until, U64::from(1_893_456_000u64));
    }

    #[test]
    fn case_insensitive_bool() {
        let headers = headers_from(&[(headers::TRUSTED, "TRUE")]);
        let perms = RpcPermissions::from_headers(&headers).unwrap().unwrap();
        assert!(perms.trusted);
    }

    #[test]
    fn malformed_int_is_rejected() {
        let headers = headers_from(&[(headers::MAX_OPS_IN_POOL_FOR_SENDER, "not-a-number")]);
        let err = RpcPermissions::from_headers(&headers).unwrap_err();
        assert_eq!(err.header, headers::MAX_OPS_IN_POOL_FOR_SENDER);
    }

    #[test]
    fn malformed_bool_is_rejected() {
        let headers = headers_from(&[(headers::TRUSTED, "yes")]);
        let err = RpcPermissions::from_headers(&headers).unwrap_err();
        assert_eq!(err.header, headers::TRUSTED);
    }

    #[test]
    fn max_cost_requires_hex_prefix() {
        let headers = headers_from(&[
            (headers::SPONSORSHIP_MAX_COST, "1000"),
            (headers::SPONSORSHIP_VALID_UNTIL, "10"),
        ]);
        let err = RpcPermissions::from_headers(&headers).unwrap_err();
        assert_eq!(err.header, headers::SPONSORSHIP_MAX_COST);
    }

    #[test]
    fn half_set_sponsorship_max_cost_only_is_rejected() {
        let headers = headers_from(&[(headers::SPONSORSHIP_MAX_COST, "0x10")]);
        let err = RpcPermissions::from_headers(&headers).unwrap_err();
        assert_eq!(err.header, headers::SPONSORSHIP_VALID_UNTIL);
    }

    #[test]
    fn half_set_sponsorship_valid_until_only_is_rejected() {
        let headers = headers_from(&[(headers::SPONSORSHIP_VALID_UNTIL, "10")]);
        let err = RpcPermissions::from_headers(&headers).unwrap_err();
        assert_eq!(err.header, headers::SPONSORSHIP_MAX_COST);
    }
}
