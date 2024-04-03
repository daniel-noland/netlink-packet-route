// SPDX-License-Identifier: MIT

/// flower filter
///
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    DecodeError,
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u32,
    traits::Parseable,
};

use crate::tc::TcHandle;

const TCA_FLOWER_UNSPEC: u16 = 0;
const TCA_FLOWER_CLASSID: u16 = 1;
const TCA_FLOWER_INDEV: u16 = 2;
const TCA_FLOWER_ACT: u16 = 3;
const TCA_FLOWER_KEY_ETH_DST: u16 = 4;
const TCA_FLOWER_KEY_ETH_DST_MASK: u16 = 5;
const TCA_FLOWER_KEY_ETH_SRC: u16 = 6;
const TCA_FLOWER_KEY_ETH_SRC_MASK: u16 = 7;
const TCA_FLOWER_KEY_ETH_TYPE: u16 = 8;
const TCA_FLOWER_KEY_IP_PROTO: u16 = 9;
const TCA_FLOWER_KEY_IPV4_SRC: u16 = 10;
const TCA_FLOWER_KEY_IPV4_SRC_MASK: u16 = 11;
const TCA_FLOWER_KEY_IPV4_DST: u16 = 12;
const TCA_FLOWER_KEY_IPV4_DST_MASK: u16 = 13;
const TCA_FLOWER_KEY_IPV6_SRC: u16 = 14;
const TCA_FLOWER_KEY_IPV6_SRC_MASK: u16 = 15;
const TCA_FLOWER_KEY_IPV6_DST: u16 = 16;
const TCA_FLOWER_KEY_IPV6_DST_MASK: u16 = 17;
const TCA_FLOWER_KEY_TCP_SRC: u16 = 18;
const TCA_FLOWER_KEY_TCP_DST: u16 = 19;
const TCA_FLOWER_KEY_UDP_SRC: u16 = 20;
const TCA_FLOWER_KEY_UDP_DST: u16 = 21;
const TCA_FLOWER_FLAGS: u16 = 22;
const TCA_FLOWER_KEY_VLAN_ID: u16 = 23;
const TCA_FLOWER_KEY_VLAN_PRIO: u16 = 24;
const TCA_FLOWER_KEY_VLAN_ETH_TYPE: u16 = 25;
const TCA_FLOWER_KEY_ENC_KEY_ID: u16 = 26;
const TCA_FLOWER_KEY_ENC_IPV4_SRC: u16 = 27;
const TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK: u16 = 28;
const TCA_FLOWER_KEY_ENC_IPV4_DST: u16 = 29;
const TCA_FLOWER_KEY_ENC_IPV4_DST_MASK: u16 = 30;
const TCA_FLOWER_KEY_ENC_IPV6_SRC: u16 = 31;
const TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK: u16 = 32;
const TCA_FLOWER_KEY_ENC_IPV6_DST: u16 = 33;
const TCA_FLOWER_KEY_ENC_IPV6_DST_MASK: u16 = 34;
const TCA_FLOWER_KEY_TCP_SRC_MASK: u16 = 35;
const TCA_FLOWER_KEY_TCP_DST_MASK: u16 = 36;
const TCA_FLOWER_KEY_UDP_SRC_MASK: u16 = 37;
const TCA_FLOWER_KEY_UDP_DST_MASK: u16 = 38;
const TCA_FLOWER_KEY_SCTP_SRC_MASK: u16 = 39;
const TCA_FLOWER_KEY_SCTP_DST_MASK: u16 = 40;
const TCA_FLOWER_KEY_SCTP_SRC: u16 = 41;
const TCA_FLOWER_KEY_SCTP_DST: u16 = 42;
const TCA_FLOWER_KEY_ENC_UDP_SRC_PORT: u16 = 43;
const TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK: u16 = 44;
const TCA_FLOWER_KEY_ENC_UDP_DST_PORT: u16 = 45;
const TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK: u16 = 46;
const TCA_FLOWER_KEY_FLAGS: u16 = 47;
const TCA_FLOWER_KEY_FLAGS_MASK: u16 = 48;
const TCA_FLOWER_KEY_ICMPV4_CODE: u16 = 49;
const TCA_FLOWER_KEY_ICMPV4_CODE_MASK: u16 = 50;
const TCA_FLOWER_KEY_ICMPV4_TYPE: u16 = 51;
const TCA_FLOWER_KEY_ICMPV4_TYPE_MASK: u16 = 52;
const TCA_FLOWER_KEY_ICMPV6_CODE: u16 = 53;
const TCA_FLOWER_KEY_ICMPV6_CODE_MASK: u16 = 54;
const TCA_FLOWER_KEY_ICMPV6_TYPE: u16 = 55;
const TCA_FLOWER_KEY_ICMPV6_TYPE_MASK: u16 = 56;
const TCA_FLOWER_KEY_ARP_SIP: u16 = 57;
const TCA_FLOWER_KEY_ARP_SIP_MASK: u16 = 58;
const TCA_FLOWER_KEY_ARP_TIP: u16 = 59;
const TCA_FLOWER_KEY_ARP_TIP_MASK: u16 = 60;
const TCA_FLOWER_KEY_ARP_OP: u16 = 61;
const TCA_FLOWER_KEY_ARP_OP_MASK: u16 = 62;
const TCA_FLOWER_KEY_ARP_SHA: u16 = 63;
const TCA_FLOWER_KEY_ARP_SHA_MASK: u16 = 64;
const TCA_FLOWER_KEY_ARP_THA: u16 = 65;
const TCA_FLOWER_KEY_ARP_THA_MASK: u16 = 66;
const TCA_FLOWER_KEY_MPLS_TTL: u16 = 67;
const TCA_FLOWER_KEY_MPLS_BOS: u16 = 68;
const TCA_FLOWER_KEY_MPLS_TC: u16 = 69;
const TCA_FLOWER_KEY_MPLS_LABEL: u16 = 70;
const TCA_FLOWER_KEY_TCP_FLAGS: u16 = 71;
const TCA_FLOWER_KEY_TCP_FLAGS_MASK: u16 = 72;
const TCA_FLOWER_KEY_IP_TOS: u16 = 73;
const TCA_FLOWER_KEY_IP_TOS_MASK: u16 = 74;
const TCA_FLOWER_KEY_IP_TTL: u16 = 75;
const TCA_FLOWER_KEY_IP_TTL_MASK: u16 = 76;
const TCA_FLOWER_KEY_CVLAN_ID: u16 = 77;
const TCA_FLOWER_KEY_CVLAN_PRIO: u16 = 78;
const TCA_FLOWER_KEY_CVLAN_ETH_TYPE: u16 = 79;
const TCA_FLOWER_KEY_ENC_IP_TOS: u16 = 80;
const TCA_FLOWER_KEY_ENC_IP_TOS_MASK: u16 = 81;
const TCA_FLOWER_KEY_ENC_IP_TTL: u16 = 82;
const TCA_FLOWER_KEY_ENC_IP_TTL_MASK: u16 = 83;
const TCA_FLOWER_KEY_ENC_OPTS: u16 = 84;
const TCA_FLOWER_KEY_ENC_OPTS_MASK: u16 = 85;
const TCA_FLOWER_IN_HW_COUNT: u16 = 86;
const TCA_FLOWER_KEY_PORT_SRC_MIN: u16 = 87;
const TCA_FLOWER_KEY_PORT_SRC_MAX: u16 = 88;
const TCA_FLOWER_KEY_PORT_DST_MIN: u16 = 89;
const TCA_FLOWER_KEY_PORT_DST_MAX: u16 = 90;
const TCA_FLOWER_KEY_CT_STATE: u16 = 91;
const TCA_FLOWER_KEY_CT_STATE_MASK: u16 = 92;
const TCA_FLOWER_KEY_CT_ZONE: u16 = 93;
const TCA_FLOWER_KEY_CT_ZONE_MASK: u16 = 94;
const TCA_FLOWER_KEY_CT_MARK: u16 = 95;
const TCA_FLOWER_KEY_CT_MARK_MASK: u16 = 96;
const TCA_FLOWER_KEY_CT_LABELS: u16 = 97;
const TCA_FLOWER_KEY_CT_LABELS_MASK: u16 = 98;
const TCA_FLOWER_KEY_MPLS_OPTS: u16 = 99;
const TCA_FLOWER_KEY_HASH: u16 = 100;
const TCA_FLOWER_KEY_HASH_MASK: u16 = 101;
const TCA_FLOWER_KEY_NUM_OF_VLANS: u16 = 102;
const TCA_FLOWER_KEY_PPPOE_SID: u16 = 103;
const TCA_FLOWER_KEY_PPP_PROTO: u16 = 104;
const TCA_FLOWER_KEY_L2TPV3_SID: u16 = 105;
const TCA_FLOWER_L2_MISS: u16 = 106;
const TCA_FLOWER_KEY_CFM: u16 = 107;
const TCA_FLOWER_KEY_SPI: u16 = 108;
const TCA_FLOWER_KEY_SPI_MASK: u16 = 109;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcFilterFlower {}

impl TcFilterFlower {
    pub const KIND: &'static str = "flower";
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcFilterFlowerOption {
    ClassId(TcHandle),
    Indev(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for TcFilterFlowerOption {
    fn value_len(&self) -> usize {
        match self {
            Self::Indev(b) => b.len(),
            Self::ClassId(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::ClassId(_) => TCA_FLOWER_CLASSID,
            Self::Indev(_) => TCA_FLOWER_INDEV,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Indev(b) => buffer.copy_from_slice(b.as_slice()),
            Self::ClassId(i) => NativeEndian::write_u32(buffer, (*i).into()),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
for TcFilterFlowerOption
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_FLOWER_CLASSID => Self::ClassId(TcHandle::from(
                parse_u32(payload).context("failed to parse TCA_FLOWER_CLASSID")?,
            )),
            TCA_FLOWER_INDEV => Self::Indev(payload.to_vec()),
            _ => Self::Other(
                DefaultNla::parse(buf).context("failed to parse flower nla")?,
            ),
        })
    }
}
