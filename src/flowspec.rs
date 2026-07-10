//! FlowSpec v1/v2 parsing (RFC 8955 IPv4, RFC 8956 IPv6).

use inetnum::addr::Prefix;
use crate::bgp::{nlri::common::prefix_bits_to_bytes, types::Afi};
use crate::bgp::nlri::flowspec::FlowSpecNlri;
use crate::util::parser::ParseError;
use log::debug;
use octseq::{Octets, Parser};

use std::cmp::{min, Ordering};
use std::fmt;
use std::net::IpAddr;

fn op_to_len(op: u8) -> usize {
    match (op & 0b00110000) >> 4 {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => panic!("impossible len bits in NumericOp")
    }
}

pub struct NumericOp(u8, u64);
impl NumericOp {
    pub fn end_of_list(&self) -> bool {
        self.0 & 0x80 == 0x80
    }

    pub fn and(&self) -> bool {
        self.0 & 0x40 == 0x40
    }

    pub fn length(&self) -> usize {
        op_to_len(self.0)
    }

    pub fn lt(&self) -> bool {
        self.0 & 0x04 == 0x04
    }

    pub fn gt(&self) -> bool {
        self.0 & 0x02 == 0x02
    }

    pub fn eq(&self) -> bool {
        self.0 & 0x01 == 0x01
    }

    pub fn value(&self) -> u64 {
        self.1
    }
}

impl fmt::Display for NumericOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 & 0x07 {
            0b000 => write!(f, "false"),
            0b001 => write!(f, "={}", self.1),
            0b010 => write!(f, ">{}", self.1),
            0b011 => write!(f, ">={}", self.1),
            0b100 => write!(f, "<{}", self.1),
            0b101 => write!(f, "<={}", self.1),
            0b110 => write!(f, "!={}", self.1),
            0b111 => write!(f, "any"),
            _ => unreachable!(),
        }
    }
}

pub struct BitmaskOp(u8, u64);
impl BitmaskOp {
    pub fn end_of_list(&self) -> bool {
        self.0 & 0x80 == 0x80
    }

    pub fn and(&self) -> bool {
        self.0 & 0x40 == 0x40
    }

    pub fn not(&self) -> bool {
        self.0 & 0x02 == 0x02
    }

    pub fn match_exact(&self) -> bool {
        self.0 & 0x01 == 0x01
    }

    pub fn value(&self) -> u64 {
        self.1
    }
}

impl fmt::Display for BitmaskOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.not() {
            write!(f, "!")?;
        }
        if self.match_exact() {
            write!(f, "=")?;
        }
        write!(f, "0x{:02x}", self.1)
    }
}


#[derive(Copy, Clone, Debug)]
pub enum Component<Octets> {
    DestinationPrefix(Prefix),
    SourcePrefix(Prefix),
    /// RFC 8956 type 1: IPv6 destination prefix with pattern offset.
    DestinationPrefixV6 { prefix: Prefix, offset: u8 },
    /// RFC 8956 type 2: IPv6 source prefix with pattern offset.
    SourcePrefixV6 { prefix: Prefix, offset: u8 },
    IpProtocol(Octets),
    Port(Octets),
    DestinationPort(Octets),
    SourcePort(Octets),
    IcmpType(Octets),
    IcmpCode(Octets),
    TcpFlags(Octets), // list of (bitmask_op , value)
    PacketLength(Octets),
    DSCP(Octets),
    Fragment(Octets),
    /// RFC 8956 type 13 (IPv6 only): Flow Label, list of numeric ops.
    FlowLabel(Octets),
}

impl NumericOp {
    fn parse<R: Octets + ?Sized>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let op = parser.parse_u8()?;
        let value = match op_to_len(op) {
            1 => parser.parse_u8()? as u64,
            2 => parser.parse_u16_be()? as u64,
            4 => parser.parse_u32_be()? as u64,
            8 => parser.parse_u64_be()?,
            _ => panic!("illegal case"),
        };
        Ok(Self(op, value))
    }
}

impl BitmaskOp {
    fn parse<R: Octets + ?Sized>(parser: &mut Parser<'_, R>)
        -> Result<Self, ParseError>
    {
        let op = parser.parse_u8()?;
        let value = match op_to_len(op) {
            1 => parser.parse_u8()? as u64,
            2 => parser.parse_u16_be()? as u64,
            4 => parser.parse_u32_be()? as u64,
            8 => parser.parse_u64_be()?,
            _ => panic!("illegal case"),
        };
        Ok(Self(op, value))
    }
}

fn parse_prefix<R: Octets + ?Sized>(
    parser: &mut Parser<'_, R>,
    afi: Afi,
    prefix_bits: u8
) -> Result<Prefix, ParseError>
{
    let prefix_bytes = prefix_bits_to_bytes(prefix_bits);
    let prefix = match (afi, prefix_bytes) {
        (Afi::Ipv4, 0) => {
            Prefix::new_v4(0.into(), 0)?
        },
        (Afi::Ipv4, _b @ 5..) => {
            return Err(ParseError::form_error("illegal byte size for IPv4 NLRI"))
        },
        (Afi::Ipv4, _) => {
            let mut b = [0u8; 4];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|_e|
                    ParseError::form_error("prefix parsing failed")
            )?
        }
        (Afi::Ipv6, 0) => {
            Prefix::new_v6(0.into(), 0)?
        },
        (Afi::Ipv6, _b @ 17..) => {
            return Err(ParseError::form_error("illegal byte size for IPv6 NLRI"))
        },
        (Afi::Ipv6, _) => {
            let mut b = [0u8; 16];
            b[..prefix_bytes].copy_from_slice(parser.peek(prefix_bytes)?);
            parser.advance(prefix_bytes)?;
            Prefix::new(IpAddr::from(b), prefix_bits).map_err(|_e|
                    ParseError::form_error("prefix parsing failed")
            )?
        },
        (_, _) => {
            panic!("unimplemented")
        }
    };
    Ok(prefix)
}

/// Parse an RFC 8956 §3.1 IPv6 prefix pattern: `length, offset, pattern`,
/// where `pattern` holds bits `[offset, length)` of the address, left-packed
/// into `ceil((length - offset) / 8)` bytes. The caller has already consumed
/// `length` and `offset`.
fn parse_prefix_v6<R: Octets + ?Sized>(
    parser: &mut Parser<'_, R>,
    prefix_bits: u8,
    prefix_offset: u8,
) -> Result<Prefix, ParseError>
{
    if prefix_bits > 128 {
        return Err(ParseError::form_error("IPv6 prefix length > 128"));
    }
    if prefix_offset > prefix_bits {
        return Err(ParseError::form_error(
            "IPv6 prefix offset exceeds prefix length"
        ));
    }
    let pattern_bits = prefix_bits - prefix_offset;
    let pattern_bytes = prefix_bits_to_bytes(pattern_bits);
    if pattern_bytes > 16 {
        return Err(ParseError::form_error("illegal byte size for IPv6 NLRI"));
    }
    let mut b = [0u8; 16];
    b[..pattern_bytes].copy_from_slice(parser.peek(pattern_bytes)?);
    parser.advance(pattern_bytes)?;
    // The pattern occupies the top pattern_bits of b; shift it down so it
    // starts at bit prefix_offset of the reconstructed address.
    let addr = u128::from_be_bytes(b) >> prefix_offset;
    Prefix::new(IpAddr::from(addr.to_be_bytes()), prefix_bits).map_err(|_e|
        ParseError::form_error("prefix parsing failed")
    )
}

fn parse_numeric_op_octets<'a, R, O>(parser: &mut Parser<'a, R>)
    -> Result<O, ParseError>
where
    R: Octets<Range<'a> = O> + ?Sized
{
    let pos = parser.pos();
    let mut done = false;
    while !done {
        let op = NumericOp::parse(parser)?;
        done = op.end_of_list();
    }
    let octets_len = parser.pos() - pos;
    parser.seek(pos)?;
    Ok(parser.parse_octets(octets_len)?)
}

fn parse_bitmask_op_octets<'a, R, O>(parser: &mut Parser<'a, R>)
    -> Result<O, ParseError>
where
    R: Octets<Range<'a> = O> + ?Sized
{
    let pos = parser.pos();
    let mut done = false;
    while !done {
        let op = BitmaskOp::parse(parser)?;
        done = op.end_of_list();
    }
    let octets_len = parser.pos() - pos;
    parser.seek(pos)?;
    Ok(parser.parse_octets(octets_len)?)
}

impl<Octs> Component<Octs> {
    /// The RFC 8955/8956 component type code.
    pub fn type_code(&self) -> u8 {
        match self {
            Component::DestinationPrefix(..)
                | Component::DestinationPrefixV6 { .. } => 1,
            Component::SourcePrefix(..)
                | Component::SourcePrefixV6 { .. } => 2,
            Component::IpProtocol(..) => 3,
            Component::Port(..) => 4,
            Component::DestinationPort(..) => 5,
            Component::SourcePort(..) => 6,
            Component::IcmpType(..) => 7,
            Component::IcmpCode(..) => 8,
            Component::TcpFlags(..) => 9,
            Component::PacketLength(..) => 10,
            Component::DSCP(..) => 11,
            Component::Fragment(..) => 12,
            Component::FlowLabel(..) => 13,
        }
    }
}

impl<Octs: AsRef<[u8]>> Component<Octs> {
    /// The raw operator/value bytes for op-list components; `None` for the
    /// prefix components (types 1 and 2).
    pub fn op_bytes(&self) -> Option<&[u8]> {
        match self {
            Component::DestinationPrefix(..)
                | Component::SourcePrefix(..)
                | Component::DestinationPrefixV6 { .. }
                | Component::SourcePrefixV6 { .. } => None,
            Component::IpProtocol(o)
                | Component::Port(o)
                | Component::DestinationPort(o)
                | Component::SourcePort(o)
                | Component::IcmpType(o)
                | Component::IcmpCode(o)
                | Component::TcpFlags(o)
                | Component::PacketLength(o)
                | Component::DSCP(o)
                | Component::Fragment(o)
                | Component::FlowLabel(o) => Some(o.as_ref()),
        }
    }
}

impl<Octs: Octets> Component<Octs> {
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>, afi: Afi)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs> + ?Sized
    {
        let typ = parser.parse_u8()?;
        let res = match typ {
            1 => {
                let prefix_bits = parser.parse_u8()?;
                match afi {
                    Afi::Ipv4 => {
                        let pfx =
                            parse_prefix(parser, Afi::Ipv4, prefix_bits)?;
                        Component::DestinationPrefix(pfx)
                    }
                    Afi::Ipv6 => {
                        let offset = parser.parse_u8()?;
                        let prefix =
                            parse_prefix_v6(parser, prefix_bits, offset)?;
                        Component::DestinationPrefixV6 { prefix, offset }
                    }
                    _ => {
                        return Err(ParseError::form_error(
                            "illegal AFI for FlowSpec"
                        ))
                    }
                }
            },
            2 => {
                let prefix_bits = parser.parse_u8()?;
                match afi {
                    Afi::Ipv4 => {
                        let pfx =
                            parse_prefix(parser, Afi::Ipv4, prefix_bits)?;
                        Component::SourcePrefix(pfx)
                    }
                    Afi::Ipv6 => {
                        let offset = parser.parse_u8()?;
                        let prefix =
                            parse_prefix_v6(parser, prefix_bits, offset)?;
                        Component::SourcePrefixV6 { prefix, offset }
                    }
                    _ => {
                        return Err(ParseError::form_error(
                            "illegal AFI for FlowSpec"
                        ))
                    }
                }
            },
            3 => Component::IpProtocol(parse_numeric_op_octets(parser)?),
            4 => Component::Port(parse_numeric_op_octets(parser)?),
            5 => Component::DestinationPort(parse_numeric_op_octets(parser)?),
            6 => Component::SourcePort(parse_numeric_op_octets(parser)?),
            7 => Component::IcmpType(parse_numeric_op_octets(parser)?),
            8 => Component::IcmpCode(parse_numeric_op_octets(parser)?),
            9 => Component::TcpFlags(parse_bitmask_op_octets(parser)?),
            10 => Component::PacketLength(parse_numeric_op_octets(parser)?),
            11 => Component::DSCP(parse_numeric_op_octets(parser)?),
            12 => Component::Fragment(parse_bitmask_op_octets(parser)?),
            13 => {
                if afi != Afi::Ipv6 {
                    return Err(ParseError::form_error(
                        "Flow Label component is IPv6-only"
                    ));
                }
                Component::FlowLabel(parse_numeric_op_octets(parser)?)
            },
            _ => {
                debug!("unimplemented flowspec type {}", typ);
                return Err(ParseError::Unsupported)
            }
        };

        Ok(res)
    }
}

fn fmt_numeric_ops(raw: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut parser = Parser::from_ref(raw);
    let mut first = true;
    while parser.remaining() > 0 {
        let op = match NumericOp::parse(&mut parser) {
            Ok(op) => op,
            Err(_) => return write!(f, "<malformed-ops>"),
        };
        if !first {
            write!(f, "{}", if op.and() { " && " } else { " || " })?;
        }
        first = false;
        write!(f, "{}", op)?;
        if op.end_of_list() {
            break;
        }
    }
    Ok(())
}

fn fmt_bitmask_ops(raw: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut parser = Parser::from_ref(raw);
    let mut first = true;
    while parser.remaining() > 0 {
        let op = match BitmaskOp::parse(&mut parser) {
            Ok(op) => op,
            Err(_) => return write!(f, "<malformed-ops>"),
        };
        if !first {
            write!(f, "{}", if op.and() { " && " } else { " || " })?;
        }
        first = false;
        write!(f, "{}", op)?;
        if op.end_of_list() {
            break;
        }
    }
    Ok(())
}

impl<Octs: AsRef<[u8]>> fmt::Display for Component<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Component::DestinationPrefix(p) => write!(f, "dst {}", p),
            Component::SourcePrefix(p) => write!(f, "src {}", p),
            Component::DestinationPrefixV6 { prefix, offset } => {
                if *offset == 0 {
                    write!(f, "dst {}", prefix)
                } else {
                    write!(f, "dst {} offset {}", prefix, offset)
                }
            }
            Component::SourcePrefixV6 { prefix, offset } => {
                if *offset == 0 {
                    write!(f, "src {}", prefix)
                } else {
                    write!(f, "src {} offset {}", prefix, offset)
                }
            }
            Component::IpProtocol(o) => {
                write!(f, "proto ")?;
                fmt_numeric_ops(o.as_ref(), f)
            }
            Component::Port(o) => {
                write!(f, "port ")?;
                fmt_numeric_ops(o.as_ref(), f)
            }
            Component::DestinationPort(o) => {
                write!(f, "dport ")?;
                fmt_numeric_ops(o.as_ref(), f)
            }
            Component::SourcePort(o) => {
                write!(f, "sport ")?;
                fmt_numeric_ops(o.as_ref(), f)
            }
            Component::IcmpType(o) => {
                write!(f, "icmp-type ")?;
                fmt_numeric_ops(o.as_ref(), f)
            }
            Component::IcmpCode(o) => {
                write!(f, "icmp-code ")?;
                fmt_numeric_ops(o.as_ref(), f)
            }
            Component::TcpFlags(o) => {
                write!(f, "tcp-flags ")?;
                fmt_bitmask_ops(o.as_ref(), f)
            }
            Component::PacketLength(o) => {
                write!(f, "pkt-len ")?;
                fmt_numeric_ops(o.as_ref(), f)
            }
            Component::DSCP(o) => {
                write!(f, "dscp ")?;
                fmt_numeric_ops(o.as_ref(), f)
            }
            Component::Fragment(o) => {
                write!(f, "frag ")?;
                fmt_bitmask_ops(o.as_ref(), f)
            }
            Component::FlowLabel(o) => {
                write!(f, "flow-label ")?;
                fmt_numeric_ops(o.as_ref(), f)
            }
        }
    }
}

fn addr_bits(prefix: &Prefix) -> u128 {
    match prefix.addr() {
        IpAddr::V4(a) => (u32::from(a) as u128) << 96,
        IpAddr::V6(a) => u128::from(a),
    }
}

/// RFC 8955 §5.1 (as updated by RFC 8956 §5.1) order of traffic filtering
/// rules. `Ordering::Less` means `a` has precedence over (sorts before) `b`.
///
/// Falls back to a plain byte-wise comparison of the raw NLRI if either NLRI
/// fails to parse.
pub fn rfc8955_cmp<A, B>(a: &FlowSpecNlri<A>, b: &FlowSpecNlri<B>) -> Ordering
where
    A: Octets,
    B: Octets,
{
    let mut ia = a.components();
    let mut ib = b.components();
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return Ordering::Equal,
            // End-of-list counts as component type infinity: the rule that
            // still has components has the lower type, hence precedence.
            (Some(Ok(_)), None) => return Ordering::Less,
            (None, Some(Ok(_))) => return Ordering::Greater,
            (Some(Err(_)), _) | (_, Some(Err(_))) => {
                return a.raw().as_ref().cmp(b.raw().as_ref());
            }
            (Some(Ok(ca)), Some(Ok(cb))) => {
                match ca.type_code().cmp(&cb.type_code()) {
                    Ordering::Equal => {}
                    // Lowest component type has precedence.
                    other => return other,
                }
                let ord = match (&ca, &cb) {
                    (
                        Component::DestinationPrefix(pa),
                        Component::DestinationPrefix(pb),
                    )
                    | (
                        Component::SourcePrefix(pa),
                        Component::SourcePrefix(pb),
                    ) => prefix_cmp_8955(pa, 0, pb, 0),
                    (
                        Component::DestinationPrefixV6 {
                            prefix: pa, offset: oa
                        },
                        Component::DestinationPrefixV6 {
                            prefix: pb, offset: ob
                        },
                    )
                    | (
                        Component::SourcePrefixV6 {
                            prefix: pa, offset: oa
                        },
                        Component::SourcePrefixV6 {
                            prefix: pb, offset: ob
                        },
                    ) => prefix_cmp_8955(pa, *oa, pb, *ob),
                    _ => {
                        // Same non-prefix type: both have op bytes.
                        let x = ca.op_bytes().unwrap_or(&[]);
                        let y = cb.op_bytes().unwrap_or(&[]);
                        let common = min(x.len(), y.len());
                        match x[..common].cmp(&y[..common]) {
                            // Common part equal: longest string has
                            // precedence.
                            Ordering::Equal => y.len().cmp(&x.len()),
                            // Not equal: lowest value has precedence.
                            other => other,
                        }
                    }
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

fn prefix_cmp_8955(pa: &Prefix, oa: u8, pb: &Prefix, ob: u8) -> Ordering {
    // RFC 8956 §5.1: lowest offset has precedence.
    match oa.cmp(&ob) {
        Ordering::Equal => {}
        other => return other,
    }
    let common = min(pa.len(), pb.len());
    let mask = if common == 0 {
        0u128
    } else {
        !0u128 << (128 - u32::from(common))
    };
    match (addr_bits(pa) & mask).cmp(&(addr_bits(pb) & mask)) {
        // Common bits equal: longest (most specific) prefix has precedence.
        Ordering::Equal => pb.len().cmp(&pa.len()),
        // Not equal: lowest IP value has precedence.
        other => other,
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::nlri::flowspec::FlowSpecNlri;
    use std::str::FromStr;

    // {dst 10.0.1.0/24, proto =17, dport =53}
    const V4_RULE: &[u8] = &[
        0x0b, // NLRI length
        0x01, 0x18, 0x0a, 0x00, 0x01, // dst-prefix 10.0.1.0/24
        0x03, 0x81, 0x11, // proto == 17
        0x05, 0x81, 0x35, // dst-port == 53
    ];

    fn parse_v4(raw: &[u8]) -> FlowSpecNlri<&[u8]> {
        let mut parser = Parser::from_ref(raw);
        FlowSpecNlri::parse(&mut parser, Afi::Ipv4).unwrap()
    }

    fn parse_v6(raw: &[u8]) -> FlowSpecNlri<&[u8]> {
        let mut parser = Parser::from_ref(raw);
        FlowSpecNlri::parse(&mut parser, Afi::Ipv6).unwrap()
    }

    use crate::bgp::types::Afi;
    use octseq::Parser;

    #[test]
    fn v4_components_and_dst_prefix() {
        let nlri = parse_v4(V4_RULE);
        let comps: Vec<_> =
            nlri.components().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0].type_code(), 1);
        assert_eq!(comps[1].type_code(), 3);
        assert_eq!(comps[2].type_code(), 5);
        assert_eq!(
            nlri.dst_prefix(),
            Some(Prefix::from_str("10.0.1.0/24").unwrap())
        );
    }

    #[test]
    fn v4_display() {
        let nlri = parse_v4(V4_RULE);
        assert_eq!(nlri.to_string(), "dst 10.0.1.0/24, proto =17, dport =53");
    }

    #[test]
    fn v4_no_dst_prefix() {
        // {proto =17, sport =53}
        let raw = [0x06, 0x03, 0x81, 0x11, 0x06, 0x81, 0x35];
        let nlri = parse_v4(&raw);
        assert_eq!(nlri.dst_prefix(), None);
    }

    #[test]
    fn v6_offset_zero_round_trip() {
        // dst 2001:db8::/32 offset 0
        let raw = [0x07, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8];
        let nlri = parse_v6(&raw);
        assert_eq!(
            nlri.dst_prefix(),
            Some(Prefix::from_str("2001:db8::/32").unwrap())
        );
        assert_eq!(nlri.to_string(), "dst 2001:db8::/32");
    }

    #[test]
    fn v6_nonzero_offset() {
        // dst bits [16,32) = 0x0db8, offset 16, length 32
        let raw = [0x05, 0x01, 0x20, 0x10, 0x0d, 0xb8];
        let nlri = parse_v6(&raw);
        // offset-anchored prefixes are not usable as index keys
        assert_eq!(nlri.dst_prefix(), None);
        let comps: Vec<_> =
            nlri.components().collect::<Result<Vec<_>, _>>().unwrap();
        match comps[0] {
            Component::DestinationPrefixV6 { prefix, offset } => {
                assert_eq!(offset, 16);
                assert_eq!(
                    prefix,
                    Prefix::from_str("0:db8::/32").unwrap()
                );
            }
            _ => panic!("expected DestinationPrefixV6"),
        }
        assert_eq!(nlri.to_string(), "dst 0:db8::/32 offset 16");
    }

    #[test]
    fn v6_flow_label() {
        // {flow-label == 5} (4-byte numeric op)
        let raw = [0x06, 0x0d, 0xa1, 0x00, 0x00, 0x00, 0x05];
        let nlri = parse_v6(&raw);
        let comps: Vec<_> =
            nlri.components().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(comps[0].type_code(), 13);
        assert_eq!(nlri.to_string(), "flow-label =5");
    }

    #[test]
    fn v6_offset_exceeding_length_rejected() {
        // length 16, offset 32
        let raw = [0x04, 0x01, 0x10, 0x20, 0x0d];
        let mut parser = Parser::from_ref(&raw[..]);
        assert!(FlowSpecNlri::parse(&mut parser, Afi::Ipv6).is_err());
    }

    #[test]
    fn flow_label_rejected_under_v4() {
        let raw = [0x03, 0x0d, 0x81, 0x05];
        let mut parser = Parser::from_ref(&raw[..]);
        assert!(FlowSpecNlri::parse(&mut parser, Afi::Ipv4).is_err());
    }

    #[test]
    fn v6_components_now_validated() {
        // garbage that previously passed unchecked under v6
        let raw = [0x03, 0xff, 0xff, 0xff];
        let mut parser = Parser::from_ref(&raw[..]);
        assert!(FlowSpecNlri::parse(&mut parser, Afi::Ipv6).is_err());
    }

    #[test]
    fn display_multi_op_and_bitmask() {
        // {port >=1024 && <=2048, tcp-flags SYN}
        // port op 1: 0x13 = len2|gt|eq (>=), value 0x0400
        // port op 2: 0xd5 = eol|and|len2|lt|eq (<=), value 0x0800
        // tcp-flags op: 0x81 = eol|len1|match, value 0x02
        let raw = [
            0x0au8,
            0x04, 0x13, 0x04, 0x00, 0xd5, 0x08, 0x00,
            0x09, 0x81, 0x02,
        ];
        let nlri = parse_v4(&raw);
        assert_eq!(
            nlri.to_string(),
            "port >=1024 && <=2048, tcp-flags =0x02"
        );
    }

    #[test]
    fn rfc8955_ordering() {
        let dst_10_0_1_0_24 = parse_v4(V4_RULE);
        // {dst 10.0.1.0/25, proto =17, dport =53}
        let more_specific = parse_v4(&[
            0x0c,
            0x01, 0x19, 0x0a, 0x00, 0x01, 0x00,
            0x03, 0x81, 0x11,
            0x05, 0x81, 0x35,
        ]);
        // {dst 10.0.0.0/24 ...}
        let lower_ip = parse_v4(&[
            0x0b,
            0x01, 0x18, 0x0a, 0x00, 0x00,
            0x03, 0x81, 0x11,
            0x05, 0x81, 0x35,
        ]);
        // {proto =17}
        let no_dst = parse_v4(&[0x03, 0x03, 0x81, 0x11]);
        // {dst 10.0.1.0/24, proto =17}
        let fewer = parse_v4(&[
            0x08,
            0x01, 0x18, 0x0a, 0x00, 0x01,
            0x03, 0x81, 0x11,
        ]);

        // more specific dst prefix has precedence
        assert_eq!(
            rfc8955_cmp(&more_specific, &dst_10_0_1_0_24),
            Ordering::Less
        );
        // lower IP value has precedence
        assert_eq!(
            rfc8955_cmp(&lower_ip, &dst_10_0_1_0_24),
            Ordering::Less
        );
        // lower component type (1 vs 3) has precedence
        assert_eq!(rfc8955_cmp(&dst_10_0_1_0_24, &no_dst), Ordering::Less);
        // more components has precedence
        assert_eq!(rfc8955_cmp(&dst_10_0_1_0_24, &fewer), Ordering::Less);
        // reflexivity
        assert_eq!(
            rfc8955_cmp(&dst_10_0_1_0_24, &dst_10_0_1_0_24),
            Ordering::Equal
        );
    }
}
