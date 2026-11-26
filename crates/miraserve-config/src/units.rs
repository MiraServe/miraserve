//! Checked parsers and strongly-typed primitives for configuration units,
//! durations, byte sizes, bind addresses, and HTTP protocols.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use serde::{Serialize, Serializer};
use thiserror::Error;

/// Error returned when parsing a unit, duration, byte size, bind address, or protocol list.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UnitParseError {
    /// The input string was empty or contained only whitespace.
    #[error("value must not be empty")]
    Empty,
    /// A numeric component was invalid or missing.
    #[error("invalid numeric value in '{input}'")]
    InvalidNumber {
        /// Original raw input string.
        input: String,
    },
    /// The unit suffix was unknown or missing.
    #[error("unknown unit '{unit}' in '{input}'")]
    UnknownUnit {
        /// Unrecognized unit suffix.
        unit: String,
        /// Original raw input string.
        input: String,
    },
    /// Arithmetic overflowed the target integer representation.
    #[error("value '{input}' exceeds maximum supported range")]
    Overflow {
        /// Original raw input string.
        input: String,
    },
    /// The bind address syntax or IP literal was invalid.
    #[error("invalid bind address '{input}': {reason}")]
    InvalidBindAddr {
        /// Original raw input string.
        input: String,
        /// Specific reason parsing failed.
        reason: &'static str,
    },
    /// A protocol token was unknown or duplicated.
    #[error("invalid protocol specification '{input}': {reason}")]
    InvalidProtocol {
        /// Original raw input string.
        input: String,
        /// Specific reason parsing failed.
        reason: String,
    },
    /// An IP address or CIDR network prefix was invalid.
    #[error("invalid IP/CIDR '{input}': {reason}")]
    InvalidIpCidr {
        /// Original raw input string.
        input: String,
        /// Specific reason parsing failed.
        reason: &'static str,
    },
}

/// Strongly-typed byte size (stored in bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ByteSize(u64);

impl ByteSize {
    /// 1 KiB (1,024 bytes).
    pub const KIB: u64 = 1_024;
    /// 1 MiB (1,048,576 bytes).
    pub const MIB: u64 = 1_024 * 1_024;
    /// 1 GiB (1,073,741,824 bytes).
    pub const GIB: u64 = 1_024 * 1_024 * 1_024;
    /// 1 TiB (1,099,511,627,776 bytes).
    pub const TIB: u64 = 1_024 * 1_024 * 1_024 * 1_024;
    /// 1 KB (1,000 bytes).
    pub const KB: u64 = 1_000;
    /// 1 MB (1,000,000 bytes).
    pub const MB: u64 = 1_000_000;
    /// 1 GB (1,000,000,000 bytes).
    pub const GB: u64 = 1_000_000_000;
    /// 1 TB (1,000,000,000,000 bytes).
    pub const TB: u64 = 1_000_000_000_000;

    /// Constructs a [`ByteSize`] from a raw byte count.
    #[must_use]
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Returns the raw byte count.
    #[must_use]
    pub const fn as_bytes(self) -> u64 {
        self.0
    }

    /// Parses a human-readable byte size such as `"50MB"`, `"16KiB"`, or `"1024B"`.
    ///
    /// Supports SI decimal suffixes (`B`, `KB`, `MB`, `GB`, `TB`) and IEC binary
    /// suffixes (`KiB`, `MiB`, `GiB`, `TiB`), matched ASCII case-insensitively.
    ///
    /// # Errors
    /// Returns [`UnitParseError`] if the string is empty, malformed, uses an unknown
    /// suffix, or overflows `u64`.
    pub fn parse(input: &str) -> Result<Self, UnitParseError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(UnitParseError::Empty);
        }

        let digit_end = trimmed
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(trimmed.len());
        let (num_str, unit_raw) = trimmed.split_at(digit_end);

        if num_str.is_empty() {
            return Err(UnitParseError::InvalidNumber {
                input: input.to_owned(),
            });
        }

        let amount: u64 = num_str.parse().map_err(|_| UnitParseError::Overflow {
            input: input.to_owned(),
        })?;

        let unit = unit_raw.trim();
        let multiplier = match unit.to_ascii_lowercase().as_str() {
            "" | "b" => 1_u64,
            "kb" => Self::KB,
            "mb" => Self::MB,
            "gb" => Self::GB,
            "tb" => Self::TB,
            "kib" => Self::KIB,
            "mib" => Self::MIB,
            "gib" => Self::GIB,
            "tib" => Self::TIB,
            _ => {
                return Err(UnitParseError::UnknownUnit {
                    unit: unit.to_owned(),
                    input: input.to_owned(),
                });
            }
        };

        let bytes = amount
            .checked_mul(multiplier)
            .ok_or_else(|| UnitParseError::Overflow {
                input: input.to_owned(),
            })?;

        Ok(Self(bytes))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}B", self.0)
    }
}

/// Parses a human-readable duration string such as `"500ms"`, `"5s"`, `"1m"`, `"2h"`,
/// `"7d"`, or compound forms like `"1m30s"`.
///
/// # Errors
/// Returns [`UnitParseError`] if the string is empty, contains invalid digits or units,
/// or overflows `Duration`.
pub fn parse_duration(input: &str) -> Result<Duration, UnitParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(UnitParseError::Empty);
    }

    let mut rest = trimmed;
    let mut total = Duration::ZERO;
    let mut parsed_any = false;

    while !rest.is_empty() {
        let digit_end = rest
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(rest.len());
        let (num_str, after_num) = rest.split_at(digit_end);

        if num_str.is_empty() {
            return Err(UnitParseError::InvalidNumber {
                input: input.to_owned(),
            });
        }

        let unit_end = after_num
            .find(|ch: char| !ch.is_ascii_alphabetic())
            .unwrap_or(after_num.len());
        let (unit_str, remaining) = after_num.split_at(unit_end);

        if unit_str.is_empty() {
            return Err(UnitParseError::UnknownUnit {
                unit: String::new(),
                input: input.to_owned(),
            });
        }

        let value: u64 = num_str.parse().map_err(|_| UnitParseError::Overflow {
            input: input.to_owned(),
        })?;

        let segment = match unit_str {
            "ms" => Duration::from_millis(value),
            "s" => Duration::from_secs(value),
            "m" => value
                .checked_mul(60)
                .map(Duration::from_secs)
                .ok_or_else(|| UnitParseError::Overflow {
                    input: input.to_owned(),
                })?,
            "h" => value
                .checked_mul(3_600)
                .map(Duration::from_secs)
                .ok_or_else(|| UnitParseError::Overflow {
                    input: input.to_owned(),
                })?,
            "d" => value
                .checked_mul(86_400)
                .map(Duration::from_secs)
                .ok_or_else(|| UnitParseError::Overflow {
                    input: input.to_owned(),
                })?,
            _ => {
                return Err(UnitParseError::UnknownUnit {
                    unit: unit_str.to_owned(),
                    input: input.to_owned(),
                });
            }
        };

        total = total
            .checked_add(segment)
            .ok_or_else(|| UnitParseError::Overflow {
                input: input.to_owned(),
            })?;
        parsed_any = true;
        rest = remaining;
    }

    if !parsed_any {
        return Err(UnitParseError::Empty);
    }

    Ok(total)
}

/// Serializes a [`Duration`] as total milliseconds for structured JSON output.
pub(crate) fn serialize_duration_ms<S>(
    duration: &Duration,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u128(duration.as_millis())
}

/// Serializes an optional [`Duration`] as optional milliseconds for JSON output.
#[allow(clippy::ref_option)] // Required signature for serde `serialize_with`
pub(crate) fn serialize_opt_duration_ms<S>(
    duration: &Option<Duration>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match duration {
        Some(d) => serializer.serialize_some(&d.as_millis()),
        None => serializer.serialize_none(),
    }
}

/// Parsed listener bind address such as `":443"`, `"0.0.0.0:443"`, or `"[::]:443"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BindAddr {
    /// Explicit IP address to bind, or `None` for wildcard (`:port`).
    pub host: Option<IpAddr>,
    /// TCP/UDP port number (`1..=65535`).
    pub port: u16,
}

impl BindAddr {
    /// Parses a bind address in `:port`, `ipv4:port`, or `[ipv6]:port` form.
    ///
    /// # Errors
    /// Returns [`UnitParseError`] if the address syntax is malformed, the IP address
    /// is invalid, or the port is `0` or out of range.
    pub fn parse(input: &str) -> Result<Self, UnitParseError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(UnitParseError::InvalidBindAddr {
                input: input.to_owned(),
                reason: "bind address must not be empty",
            });
        }

        let (host, port_str) = if let Some(port_part) = trimmed.strip_prefix(':') {
            (None, port_part)
        } else if let Some(rest) = trimmed.strip_prefix('[') {
            let (ip_part, after_bracket) =
                rest.split_once(']')
                    .ok_or_else(|| UnitParseError::InvalidBindAddr {
                        input: input.to_owned(),
                        reason: "unterminated IPv6 bracket '['",
                    })?;
            let port_part =
                after_bracket
                    .strip_prefix(':')
                    .ok_or_else(|| UnitParseError::InvalidBindAddr {
                        input: input.to_owned(),
                        reason: "expected ':<port>' after IPv6 address",
                    })?;
            let ip = IpAddr::from_str(ip_part).map_err(|_| UnitParseError::InvalidBindAddr {
                input: input.to_owned(),
                reason: "invalid IPv6 address literal",
            })?;
            if !ip.is_ipv6() {
                return Err(UnitParseError::InvalidBindAddr {
                    input: input.to_owned(),
                    reason: "bracketed host must be an IPv6 address",
                });
            }
            (Some(ip), port_part)
        } else {
            let (ip_part, port_part) =
                trimmed
                    .rsplit_once(':')
                    .ok_or_else(|| UnitParseError::InvalidBindAddr {
                        input: input.to_owned(),
                        reason: "expected '<ip>:<port>' or ':<port>'",
                    })?;
            let ip = IpAddr::from_str(ip_part).map_err(|_| UnitParseError::InvalidBindAddr {
                input: input.to_owned(),
                reason: "invalid IP address literal (wrap IPv6 addresses in '[...]')",
            })?;
            if !ip.is_ipv4() {
                return Err(UnitParseError::InvalidBindAddr {
                    input: input.to_owned(),
                    reason: "IPv6 addresses must be enclosed in '[...]'",
                });
            }
            (Some(ip), port_part)
        };

        let port: u16 = port_str
            .parse()
            .map_err(|_| UnitParseError::InvalidBindAddr {
                input: input.to_owned(),
                reason: "port must be an integer between 1 and 65535",
            })?;

        if port == 0 {
            return Err(UnitParseError::InvalidBindAddr {
                input: input.to_owned(),
                reason: "port 0 is not allowed in static listener configuration",
            });
        }

        Ok(Self { host, port })
    }

    /// Returns `true` if two bind addresses collide on the same port and address family.
    ///
    /// Bare `":port"` (`host == None`) binds **dual-stack** (`0.0.0.0:port` + `[::]:port` with
    /// `IPV6_V6ONLY = true`), so it conflicts with any IPv4 or IPv6 listener on the same port.
    /// Explicit `"0.0.0.0:port"` and `"[::]:port"` bind separate address families and do NOT
    /// conflict with each other.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        if self.port != other.port {
            return false;
        }
        match (self.host, other.host) {
            // Bare `:port` is dual-stack (IPv4 + IPv6 wildcard) and collides with any listener on the same port.
            (None, _) | (_, None) => true,
            (Some(IpAddr::V4(v4a)), Some(IpAddr::V4(v4b))) => {
                v4a == v4b || v4a.is_unspecified() || v4b.is_unspecified()
            }
            (Some(IpAddr::V6(v6a)), Some(IpAddr::V6(v6b))) => {
                v6a == v6b || v6a.is_unspecified() || v6b.is_unspecified()
            }
            (Some(IpAddr::V4(_)), Some(IpAddr::V6(_)))
            | (Some(IpAddr::V6(_)), Some(IpAddr::V4(_))) => false,
        }
    }
}

impl fmt::Display for BindAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.host {
            None => write!(f, ":{}", self.port),
            Some(IpAddr::V4(v4)) => write!(f, "{v4}:{}", self.port),
            Some(IpAddr::V6(v6)) => write!(f, "[{v6}]:{}", self.port),
        }
    }
}

impl Serialize for BindAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Supported HTTP transport protocols on a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP/3 over QUIC (UDP).
    H3,
    /// HTTP/2 over TLS (TCP).
    H2,
    /// HTTP/1.1 over TCP/TLS.
    H1,
}

impl Protocol {
    /// Parses a comma-separated list of protocols (e.g. `"h3,h2,h1"`).
    ///
    /// # Errors
    /// Returns [`UnitParseError`] if the list is empty, contains an unrecognized token,
    /// or lists the same protocol more than once.
    pub fn parse_list(input: &str) -> Result<Vec<Self>, UnitParseError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(UnitParseError::InvalidProtocol {
                input: input.to_owned(),
                reason: "protocol list must not be empty".to_owned(),
            });
        }

        let mut protocols = Vec::new();
        for raw_token in trimmed.split(',') {
            let token = raw_token.trim();
            let proto = match token {
                "h3" => Self::H3,
                "h2" => Self::H2,
                "h1" => Self::H1,
                other => {
                    return Err(UnitParseError::InvalidProtocol {
                        input: input.to_owned(),
                        reason: format!("unknown protocol '{other}' (expected h3, h2, or h1)"),
                    });
                }
            };
            if protocols.contains(&proto) {
                return Err(UnitParseError::InvalidProtocol {
                    input: input.to_owned(),
                    reason: format!("duplicate protocol '{token}'"),
                });
            }
            protocols.push(proto);
        }

        Ok(protocols)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::H3 => f.write_str("h3"),
            Self::H2 => f.write_str("h2"),
            Self::H1 => f.write_str("h1"),
        }
    }
}

/// Strongly-typed IPv4/IPv6 address or CIDR prefix (`"10.0.0.0/8"`, `"192.168.1.5"`, `"2001:db8::/32"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    /// Parses a single IP literal (implying `/32` or `/128`) or CIDR range (`ip/prefix`).
    /// IPv4-mapped IPv6 addresses (e.g. `::ffff:10.0.0.1`) are canonicalized to IPv4.
    ///
    /// # Errors
    /// Returns [`UnitParseError::InvalidIpCidr`] if the IP literal or prefix length is invalid.
    pub fn parse(input: &str) -> Result<Self, UnitParseError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(UnitParseError::InvalidIpCidr {
                input: input.to_owned(),
                reason: "IP/CIDR entry must not be empty",
            });
        }
        let (addr_part, prefix_part) = match trimmed.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (trimmed, None),
        };
        let raw_ip = IpAddr::from_str(addr_part).map_err(|_| UnitParseError::InvalidIpCidr {
            input: input.to_owned(),
            reason: "invalid IPv4 or IPv6 address literal",
        })?;
        let (ip, max_bits, adjusted_prefix) = match raw_ip {
            IpAddr::V4(v4) => (IpAddr::V4(v4), 32_u8, prefix_part),
            IpAddr::V6(v6) => {
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    if let Some(p_str) = prefix_part {
                        let v6_prefix: u8 =
                            p_str.parse().map_err(|_| UnitParseError::InvalidIpCidr {
                                input: input.to_owned(),
                                reason: "invalid CIDR prefix length",
                            })?;
                        if v6_prefix > 128 {
                            return Err(UnitParseError::InvalidIpCidr {
                                input: input.to_owned(),
                                reason: "IPv6 prefix length must be between 0 and 128",
                            });
                        }
                        if v6_prefix < 96 {
                            let masked = mask_v6(v6, v6_prefix);
                            if masked != v6 {
                                return Err(UnitParseError::InvalidIpCidr {
                                    input: input.to_owned(),
                                    reason: "CIDR has non-zero host bits set (use the network address or /128)",
                                });
                            }
                            return Ok(Self {
                                network: IpAddr::V6(masked),
                                prefix_len: v6_prefix,
                            });
                        }
                        let v4_p = v6_prefix - 96;
                        let masked = mask_v4(mapped, v4_p);
                        if masked != mapped {
                            return Err(UnitParseError::InvalidIpCidr {
                                input: input.to_owned(),
                                reason: "CIDR has non-zero host bits set (use the network address or /32)",
                            });
                        }
                        return Ok(Self {
                            network: IpAddr::V4(masked),
                            prefix_len: v4_p,
                        });
                    }
                    return Ok(Self {
                        network: IpAddr::V4(mapped),
                        prefix_len: 32,
                    });
                }
                (IpAddr::V6(v6), 128_u8, prefix_part)
            }
        };

        let prefix_len = match adjusted_prefix {
            Some(p_str) => {
                let p: u8 = p_str.parse().map_err(|_| UnitParseError::InvalidIpCidr {
                    input: input.to_owned(),
                    reason: "invalid CIDR prefix length",
                })?;
                if p > max_bits {
                    return Err(UnitParseError::InvalidIpCidr {
                        input: input.to_owned(),
                        reason: if max_bits == 32 {
                            "IPv4 prefix length must be between 0 and 32"
                        } else {
                            "IPv6 prefix length must be between 0 and 128"
                        },
                    });
                }
                p
            }
            None => max_bits,
        };

        let network = match ip {
            IpAddr::V4(v4) => IpAddr::V4(mask_v4(v4, prefix_len)),
            IpAddr::V6(v6) => IpAddr::V6(mask_v6(v6, prefix_len)),
        };
        // R6-XFF-4: Reject CIDRs with non-zero host bits (e.g. `10.0.0.1/8` instead of `10.0.0.1/32`
        // or `10.0.0.0/8`) so an operator intending a single proxy IP never silently trusts a whole /8!
        if adjusted_prefix.is_some() && network != ip {
            return Err(UnitParseError::InvalidIpCidr {
                input: input.to_owned(),
                reason: "CIDR has non-zero host bits set (use exact /32 or /128 for a single host, or zero host bits for a subnet)",
            });
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Creates a host-exact CIDR (`/32` for IPv4 or `/128` for IPv6).
    #[must_use]
    pub const fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self {
                network: IpAddr::V4(v4),
                prefix_len: 32,
            },
            IpAddr::V6(v6) => {
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    Self {
                        network: IpAddr::V4(mapped),
                        prefix_len: 32,
                    }
                } else {
                    Self {
                        network: IpAddr::V6(v6),
                        prefix_len: 128,
                    }
                }
            }
        }
    }

    /// Returns the masked network address.
    #[must_use]
    pub const fn network(self) -> IpAddr {
        self.network
    }

    /// Returns the prefix length in bits (`0..=32` for IPv4, `0..=128` for IPv6).
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Returns `true` if `ip` (canonicalizing IPv4-mapped IPv6) falls within this CIDR.
    #[must_use]
    pub fn contains(self, ip: IpAddr) -> bool {
        let canonical = ip.to_canonical();
        match (self.network, canonical) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                let net_bits = u32::from_be_bytes(net.octets());
                let target_bits = u32::from_be_bytes(target.octets());
                if self.prefix_len == 0 {
                    true
                } else {
                    let shift = 32 - u32::from(self.prefix_len);
                    (net_bits >> shift) == (target_bits >> shift)
                }
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                let net_bits = u128::from_be_bytes(net.octets());
                let target_bits = u128::from_be_bytes(target.octets());
                if self.prefix_len == 0 {
                    true
                } else {
                    let shift = 128 - u32::from(self.prefix_len);
                    (net_bits >> shift) == (target_bits >> shift)
                }
            }
            _ => false,
        }
    }
}

fn mask_v4(addr: std::net::Ipv4Addr, prefix_len: u8) -> std::net::Ipv4Addr {
    if prefix_len == 0 {
        return std::net::Ipv4Addr::UNSPECIFIED;
    }
    let shift = 32 - u32::from(prefix_len);
    let mask = u32::MAX << shift;
    std::net::Ipv4Addr::from_bits(addr.to_bits() & mask)
}

fn mask_v6(addr: std::net::Ipv6Addr, prefix_len: u8) -> std::net::Ipv6Addr {
    if prefix_len == 0 {
        return std::net::Ipv6Addr::UNSPECIFIED;
    }
    let shift = 128 - u32::from(prefix_len);
    let mask = u128::MAX << shift;
    std::net::Ipv6Addr::from_bits(addr.to_bits() & mask)
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl Serialize for IpCidr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
