use std::{cmp, fmt};

use inetnum::addr::Prefix;
use octseq::{Octets, OctetsBuilder, Parser};

use crate::util::parser::ParseError;
use crate::flowspec::Component;
use super::afisafi::Afi;


/// NLRI containing a FlowSpec v1 specification.
///
/// Also see [`crate::flowspec`].
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowSpecNlri<Octs> {
    #[allow(dead_code)]
    afi: Afi,
    raw: Octs,
}

impl<Octs> FlowSpecNlri<Octs> {
    pub fn raw(&self) -> &Octs {
        &self.raw
    }

    pub fn afi(&self) -> Afi {
        self.afi
    }
}

impl<Octs: AsRef<[u8]>> FlowSpecNlri<Octs> {
    /// Copy into an NLRI backed by owned octets of type `T`.
    pub fn to_owned_octets<T: From<Vec<u8>>>(&self) -> FlowSpecNlri<T> {
        FlowSpecNlri {
            afi: self.afi,
            raw: T::from(self.raw.as_ref().to_vec()),
        }
    }
}

impl<Octs: Octets> FlowSpecNlri<Octs> {
    /// Iterate over the typed components of this NLRI.
    ///
    /// Iteration stops after the first component that fails to parse; that
    /// failure is yielded as the final `Err` item.
    pub fn components(&self) -> ComponentIter<'_, Octs> {
        ComponentIter {
            parser: Parser::from_ref(&self.raw),
            afi: self.afi,
            errored: false,
        }
    }

    /// The destination-prefix component (type 1) usable as an index key:
    /// present for IPv4, or for IPv6 when the pattern offset is 0. `None`
    /// when the component is absent, offset-anchored, or the NLRI is
    /// malformed.
    pub fn dst_prefix(&self) -> Option<Prefix> {
        for c in self.components() {
            match c {
                Ok(Component::DestinationPrefix(p)) => return Some(p),
                Ok(Component::DestinationPrefixV6 { prefix, offset: 0 }) => {
                    return Some(prefix)
                }
                Ok(Component::DestinationPrefixV6 { .. }) => return None,
                Ok(_) => {}
                Err(_) => return None,
            }
        }
        None
    }
}

/// Iterator over the [`Component`]s of a [`FlowSpecNlri`].
pub struct ComponentIter<'a, Octs: ?Sized> {
    parser: Parser<'a, Octs>,
    afi: Afi,
    errored: bool,
}

impl<'a, Octs: Octets + ?Sized> Iterator for ComponentIter<'a, Octs> {
    type Item = Result<Component<Octs::Range<'a>>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored || self.parser.remaining() == 0 {
            return None;
        }
        match Component::parse(&mut self.parser, self.afi) {
            Ok(c) => Some(Ok(c)),
            Err(e) => {
                self.errored = true;
                Some(Err(e))
            }
        }
    }
}

impl<Octs: Octets> FlowSpecNlri<Octs> {
    pub fn parse<'a, R>(parser: &mut Parser<'a, R>, afi: Afi)
        -> Result<Self, ParseError>
    where
        R: Octets<Range<'a> = Octs> + ?Sized
    {
        let len1 = parser.parse_u8()?;
        let len: u16 = if len1 >= 0xf0 {
            let len2 = parser.parse_u8()? as u16;
            (((len1 as u16) << 8) | len2) & 0x0fff
        } else {
            len1 as u16
        };
        let pos = parser.pos();

        if usize::from(len) > parser.remaining() {
            return Err(ParseError::form_error(
                    "invalid length of FlowSpec NLRI"
            ));
        }

        match afi {
            Afi::Ipv4 | Afi::Ipv6 => {
                while parser.pos() < pos + len as usize {
                    Component::parse(parser, afi)?;
                }
            }
            _ => {
                return Err(ParseError::form_error("illegal AFI for FlowSpec"))
            }
        }
                
        parser.seek(pos)?;
        let raw = parser.parse_octets(len as usize)?;

        Ok(
            FlowSpecNlri {
                afi,
                raw
            }
        )
    }
}


impl<Octs: AsRef<[u8]>> FlowSpecNlri<Octs> {
    pub(super) fn compose_len(&self) -> usize {
        self.raw.as_ref().len()
    }

    pub(super) fn compose<Target: OctetsBuilder>(&self, target: &mut Target)
        -> Result<(), Target::AppendError> {
        // length is represented as either a single byte for everything < 240,
        // or as 1.5 bytes with the first nibble set to 0xf, so 0xfnnn.
        // This results in a max length of 4095.
        let len = self.raw.as_ref().len();
        if len >= 240 {
            target.append_slice(&
                (0xf000 | u16::try_from(len).unwrap_or(4095)).to_be_bytes()
            )?;
        } else {
            // we know the length is between 0 and 239 so we can unwrap
            target.append_slice(&[u8::try_from(len).unwrap()])?;
        }
        target.append_slice(self.raw.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Eq for FlowSpecNlri<Octs> { }

impl<Octs, Other> PartialEq<FlowSpecNlri<Other>> for FlowSpecNlri<Octs>
where Octs: AsRef<[u8]>,
      Other: AsRef<[u8]>
{
    fn eq(&self, other: &FlowSpecNlri<Other>) -> bool {
        self.afi == other.afi &&
            self.raw.as_ref() == other.raw.as_ref()
    }
}


impl<Octs> PartialOrd for FlowSpecNlri<Octs>
where Octs: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &FlowSpecNlri<Octs>) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Octs: AsRef<[u8]>> Ord for FlowSpecNlri<Octs> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.raw.as_ref().cmp(other.raw.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> fmt::Display for FlowSpecNlri<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.raw.as_ref();
        let mut parser = Parser::from_ref(raw);
        let mut first = true;
        while parser.remaining() > 0 {
            match Component::<&[u8]>::parse(&mut parser, self.afi) {
                Ok(c) => {
                    if !first {
                        write!(f, ", ")?;
                    }
                    first = false;
                    write!(f, "{}", c)?;
                }
                Err(_) => {
                    // Never fail on hostile bytes; fall back to hex.
                    if !first {
                        write!(f, ", ")?;
                    }
                    write!(f, "flowspec-raw(")?;
                    for b in raw {
                        write!(f, "{:02x}", b)?;
                    }
                    return write!(f, ")");
                }
            }
        }
        if first {
            write!(f, "flowspec-empty")?;
        }
        Ok(())
    }
}
