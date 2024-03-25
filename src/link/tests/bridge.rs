// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{DefaultNla, NlaBuffer},
    Emitable, Parseable,
};

use crate::link::{
    af_spec::VecAfSpecBridge, AfSpecBridge, AfSpecInet, AfSpecInet6,
    AfSpecUnspec, BridgeId, BridgePortMulticastRouter, BridgePortState,
    BridgeVlanInfo, Inet6CacheInfo, Inet6DevConf, Inet6IfaceFlags, InetDevConf,
    InfoBridge, InfoBridgePort, InfoData, InfoKind, InfoPortData, InfoPortKind,
    LinkAttribute, LinkFlag, LinkHeader, LinkInfo, LinkLayerType, LinkMessage,
    LinkMessageBuffer, LinkXdp, Map, State, Stats, Stats64, XdpAttached,
};
use crate::AddressFamily;

#[test]
fn test_parse_link_bridge_no_extention_mask() {
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0x35, 0x00, 0x00, 0x00, 0x43, 0x10, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x62, 0x72, 0x30, 0x00,
        0x08, 0x00, 0x0d, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x05, 0x00, 0x10, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x05, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0xdc, 0x05, 0x00, 0x00, 0x08, 0x00, 0x32, 0x00,
        0x44, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x08, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1e, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x1f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x28, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x08, 0x00, 0x29, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x08, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x3f, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x08, 0x00, 0x3b, 0x00, 0xf8, 0xff, 0x07, 0x00, 0x08, 0x00, 0x3c, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x08, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x06, 0x00,
        0x6e, 0x6f, 0x71, 0x75, 0x65, 0x75, 0x65, 0x00, 0x08, 0x00, 0x23, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2f, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x27, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x23, 0x45, 0x67,
        0x89, 0x1c, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x00, 0xcc, 0x00, 0x17, 0x00, 0x36, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x88, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x0d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x07, 0x00, 0x36, 0x00, 0x00, 0x00,
        0x1f, 0x00, 0x00, 0x00, 0x88, 0x14, 0x00, 0x00, 0x42, 0x0d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x2b, 0x00,
        0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x01, 0x12, 0x00,
        0x0b, 0x00, 0x01, 0x00, 0x62, 0x72, 0x69, 0x64, 0x67, 0x65, 0x00, 0x00,
        0x9c, 0x01, 0x02, 0x00, 0x0c, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x13, 0x00, 0xa6, 0x37, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0xdb, 0x05, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00, 0xc7, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
        0xcf, 0x07, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x2f, 0x75, 0x00, 0x00,
        0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00,
        0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0b, 0x00,
        0x80, 0x00, 0x00, 0x23, 0x45, 0x67, 0x89, 0x1c, 0x0c, 0x00, 0x0a, 0x00,
        0x80, 0x00, 0x00, 0x23, 0x45, 0x67, 0x89, 0x1c, 0x06, 0x00, 0x0c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x01, 0x80, 0xc2, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x81, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x27, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x29, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x16, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x17, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x2a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1a, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x1b, 0x00, 0x00, 0x10, 0x00, 0x00, 0x08, 0x00, 0x1c, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x2b, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x2c, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x1e, 0x00, 0x63, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x1f, 0x00, 0x8f, 0x65, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x20, 0x00, 0x9b, 0x63, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x21, 0x00, 0xd3, 0x30, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x22, 0x00, 0xe7, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x23, 0x00, 0x34, 0x0c, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x26, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x1a, 0x00, 0x8c, 0x00, 0x02, 0x00,
        0x88, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x27, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x10, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x10, 0x00, 0x00, 0x80, 0x14, 0x00, 0x05, 0x00, 0xff, 0xff, 0x00, 0x00,
        0xe7, 0xc4, 0x92, 0x01, 0x18, 0x92, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0xf0, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0xdc, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xa0, 0x0f, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x3a, 0x09, 0x00, 0x80, 0x51, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x58, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x60, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xee, 0x36, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x3e, 0x80,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 53,
            link_layer_type: LinkLayerType::Ether,
            flags: vec![
                LinkFlag::Broadcast,
                LinkFlag::LowerUp,
                LinkFlag::Multicast,
                LinkFlag::Running,
                LinkFlag::Up,
            ],
            change_mask: vec![],
        },
        attributes: vec![
            LinkAttribute::IfName("br0".into()),
            LinkAttribute::TxQueueLen(1000),
            LinkAttribute::OperState(State::Up),
            LinkAttribute::Mode(0),
            LinkAttribute::Mtu(1500),
            LinkAttribute::MinMtu(68),
            LinkAttribute::MaxMtu(65535),
            LinkAttribute::Group(0),
            LinkAttribute::Promiscuity(0),
            LinkAttribute::Other(DefaultNla::new(61, vec![0, 0, 0, 0])),
            LinkAttribute::NumTxQueues(1),
            LinkAttribute::GsoMaxSegs(65535),
            LinkAttribute::GsoMaxSize(65536),
            LinkAttribute::Other(DefaultNla::new(58, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(63, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(64, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(59, vec![248, 255, 7, 0])),
            LinkAttribute::Other(DefaultNla::new(60, vec![255, 255, 0, 0])),
            LinkAttribute::NumRxQueues(1),
            LinkAttribute::Carrier(1),
            LinkAttribute::Qdisc("noqueue".to_string()),
            LinkAttribute::CarrierChanges(2),
            LinkAttribute::CarrierUpCount(1),
            LinkAttribute::CarrierDownCount(1),
            LinkAttribute::ProtoDown(0),
            LinkAttribute::Map(Map {
                memory_start: 0,
                memory_end: 0,
                base_address: 0,
                irq: 0,
                dma: 0,
                port: 0,
            }),
            LinkAttribute::Address(vec![0x00, 0x23, 0x45, 0x67, 0x89, 0x1c]),
            LinkAttribute::Broadcast(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            LinkAttribute::Stats64(Stats64 {
                rx_packets: 54,
                tx_packets: 31,
                rx_bytes: 5256,
                tx_bytes: 3394,
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 0,
                tx_dropped: 0,
                multicast: 54,
                collisions: 0,
                rx_length_errors: 0,
                rx_over_errors: 0,
                rx_crc_errors: 0,
                rx_frame_errors: 0,
                rx_fifo_errors: 0,
                rx_missed_errors: 0,
                tx_aborted_errors: 0,
                tx_carrier_errors: 0,
                tx_fifo_errors: 0,
                tx_heartbeat_errors: 0,
                tx_window_errors: 0,
                rx_compressed: 0,
                tx_compressed: 0,
                rx_nohandler: 0,
                rx_otherhost_dropped: 0,
            }),
            LinkAttribute::Stats(Stats {
                rx_packets: 54,
                tx_packets: 31,
                rx_bytes: 5256,
                tx_bytes: 3394,
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 0,
                tx_dropped: 0,
                multicast: 54,
                collisions: 0,
                rx_length_errors: 0,
                rx_over_errors: 0,
                rx_crc_errors: 0,
                rx_frame_errors: 0,
                rx_fifo_errors: 0,
                rx_missed_errors: 0,
                tx_aborted_errors: 0,
                tx_carrier_errors: 0,
                tx_fifo_errors: 0,
                tx_heartbeat_errors: 0,
                tx_window_errors: 0,
                rx_compressed: 0,
                tx_compressed: 0,
                rx_nohandler: 0,
            }),
            LinkAttribute::Xdp(vec![LinkXdp::Attached(XdpAttached::None)]),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Bridge),
                LinkInfo::Data(InfoData::Bridge(vec![
                    InfoBridge::HelloTimer(0),
                    InfoBridge::TcnTimer(0),
                    InfoBridge::TopologyChangeTimer(0),
                    InfoBridge::GcTimer(14246),
                    InfoBridge::ForwardDelay(1499),
                    InfoBridge::HelloTime(199),
                    InfoBridge::MaxAge(1999),
                    InfoBridge::AgeingTime(29999),
                    InfoBridge::StpState(0),
                    InfoBridge::Priority(32768),
                    InfoBridge::VlanFiltering(false),
                    InfoBridge::GroupFwdMask(0),
                    InfoBridge::BridgeId(BridgeId {
                        priority: 0x8000,
                        address: [0x00, 0x23, 0x45, 0x67, 0x89, 0x1c],
                    }),
                    InfoBridge::RootId(BridgeId {
                        priority: 0x8000,
                        address: [0x00, 0x23, 0x45, 0x67, 0x89, 0x1c],
                    }),
                    InfoBridge::RootPort(0),
                    InfoBridge::RootPathCost(0),
                    InfoBridge::TopologyChange(0),
                    InfoBridge::TopologyChangeDetected(0),
                    InfoBridge::GroupAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]),
                    InfoBridge::MultiBoolOpt(30064771072),
                    InfoBridge::VlanProtocol(33024),
                    InfoBridge::VlanDefaultPvid(1),
                    InfoBridge::VlanStatsEnabled(0),
                    InfoBridge::VlanStatsPerHost(0),
                    InfoBridge::MulticastRouter(1),
                    InfoBridge::MulticastSnooping(1),
                    InfoBridge::MulticastQueryUseIfaddr(0),
                    InfoBridge::MulticastQuerier(0),
                    InfoBridge::MulticastStatsEnabled(0),
                    InfoBridge::MulticastHashElasticity(16),
                    InfoBridge::MulticastHashMax(4096),
                    InfoBridge::MulticastLastMemberCount(2),
                    InfoBridge::MulticastStartupQueryCount(2),
                    InfoBridge::MulticastIgmpVersion(2),
                    InfoBridge::MulticastMldVersion(1),
                    InfoBridge::MulticastLastMemberInterval(99),
                    InfoBridge::MulticastMembershipInterval(25999),
                    InfoBridge::MulticastQuerierInterval(25499),
                    InfoBridge::MulticastQueryInterval(12499),
                    InfoBridge::MulticastQueryResponseInterval(999),
                    InfoBridge::MulticastStartupQueryInterval(3124),
                    InfoBridge::NfCallIpTables(0),
                    InfoBridge::NfCallIp6Tables(0),
                    InfoBridge::NfCallArpTables(0),
                ])),
            ]),
            LinkAttribute::AfSpecUnspec(vec![
                AfSpecUnspec::Inet(vec![AfSpecInet::DevConf(InetDevConf {
                    forwarding: 1,
                    mc_forwarding: 0,
                    proxy_arp: 0,
                    accept_redirects: 1,
                    secure_redirects: 1,
                    send_redirects: 1,
                    shared_media: 1,
                    rp_filter: 2,
                    accept_source_route: 0,
                    bootp_relay: 0,
                    log_martians: 0,
                    tag: 0,
                    arpfilter: 0,
                    medium_id: 0,
                    noxfrm: 0,
                    nopolicy: 0,
                    force_igmp_version: 0,
                    arp_announce: 0,
                    arp_ignore: 0,
                    promote_secondaries: 1,
                    arp_accept: 0,
                    arp_notify: 0,
                    accept_local: 0,
                    src_vmark: 0,
                    proxy_arp_pvlan: 0,
                    route_localnet: 0,
                    igmpv2_unsolicited_report_interval: 10000,
                    igmpv3_unsolicited_report_interval: 1000,
                    ignore_routes_with_linkdown: 0,
                    drop_unicast_in_l2_multicast: 0,
                    drop_gratuitous_arp: 0,
                    bc_forwarding: 0,
                    arp_evict_nocarrier: 1,
                })]),
                AfSpecUnspec::Inet6(vec![
                    AfSpecInet6::Flags(
                        Inet6IfaceFlags::RsSent | Inet6IfaceFlags::Ready,
                    ),
                    AfSpecInet6::CacheInfo(Inet6CacheInfo {
                        max_reasm_len: 65535,
                        tstamp: 26395879,
                        reachable_time: 37400,
                        retrans_time: 1000,
                    }),
                    AfSpecInet6::DevConf(Inet6DevConf {
                        forwarding: 0,
                        hoplimit: 64,
                        mtu6: 1500,
                        accept_ra: 1,
                        accept_redirects: 1,
                        autoconf: 1,
                        dad_transmits: 1,
                        rtr_solicits: -1,
                        rtr_solicit_interval: 4000,
                        rtr_solicit_delay: 1000,
                        use_tempaddr: 0,
                        temp_valid_lft: 604800,
                        temp_prefered_lft: 86400,
                        regen_max_retry: 3,
                        max_desync_factor: 600,
                        max_addresses: 16,
                        force_mld_version: 0,
                        accept_ra_defrtr: 1,
                        accept_ra_pinfo: 1,
                        accept_ra_rtr_pref: 1,
                        rtr_probe_interval: 60000,
                        accept_ra_rt_info_max_plen: 0,
                        proxy_ndp: 0,
                        optimistic_dad: 0,
                        accept_source_route: 0,
                        mc_forwarding: 0,
                        disable_ipv6: 0,
                        accept_dad: 1,
                        force_tllao: 0,
                        ndisc_notify: 0,
                        mldv1_unsolicited_report_interval: 10000,
                        mldv2_unsolicited_report_interval: 1000,
                        suppress_frag_ndisc: 1,
                        accept_ra_from_local: 0,
                        use_optimistic: 0,
                        accept_ra_mtu: 1,
                        stable_secret: 0,
                        use_oif_addrs_only: 0,
                        accept_ra_min_hop_limit: 1,
                        ignore_routes_with_linkdown: 0,
                        drop_unicast_in_l2_multicast: 0,
                        drop_unsolicited_na: 0,
                        keep_addr_on_down: 0,
                        rtr_solicit_max_interval: 3600000,
                        seg6_enabled: 0,
                        seg6_require_hmac: 0,
                        enhanced_dad: 1,
                        addr_gen_mode: 0,
                        disable_policy: 0,
                        accept_ra_rt_info_min_plen: 0,
                        ndisc_tclass: 0,
                        rpl_seg_enabled: 0,
                        ra_defrtr_metric: 1024,
                        ioam6_enabled: 0,
                        ioam6_id: 65535,
                        ioam6_id_wide: -1,
                        ndisc_evict_nocarrier: 1,
                        accept_untracked_na: 0,
                        accept_ra_min_lft: 0,
                    }),
                ]),
            ]),
            LinkAttribute::Other(DefaultNla::new(32830, vec![])),
        ],
    };

    assert_eq!(
        expected,
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

#[test]
fn test_af_spec_bridge() {
    // The nlmon cannot capture AF_BRIDGE data, this is debug print of
    // example `dump_packet_link_bridge_vlan` after command:
    //  `bridge vlan add vid 2-4094 dev eth2`
    let raw: Vec<u8> = vec![
        0x08, 0x00, 0x02, 0x00, 0x06, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x08, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x10, 0x00, 0xfe, 0x0f,
    ];

    let expected = vec![
        AfSpecBridge::VlanInfo(BridgeVlanInfo { flags: 6, vid: 1 }),
        AfSpecBridge::VlanInfo(BridgeVlanInfo { flags: 8, vid: 2 }),
        AfSpecBridge::VlanInfo(BridgeVlanInfo {
            flags: 16,
            vid: 4094,
        }),
    ];

    assert_eq!(
        VecAfSpecBridge::parse(&NlaBuffer::new(&raw)).unwrap().0,
        expected
    );
}

#[test]
fn test_bridge_port_link_info() {
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x12, 0x00, 0x09, 0x00, 0x01, 0x00,
        0x76, 0x65, 0x74, 0x68, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x00,
        0x62, 0x72, 0x69, 0x64, 0x67, 0x65, 0x00, 0x00, 0x48, 0x01, 0x05, 0x00,
        0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x1c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x1b, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x1e, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x80, 0x00, 0x52, 0x54,
        0x00, 0xde, 0x0d, 0x2e, 0x0c, 0x00, 0x0e, 0x00, 0x80, 0x00, 0x52, 0x54,
        0x00, 0xde, 0x0d, 0x2e, 0x06, 0x00, 0x0f, 0x00, 0x01, 0x80, 0x00, 0x00,
        0x06, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x11, 0x00,
        0x01, 0x80, 0x00, 0x00, 0x06, 0x00, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x14, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x21, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x15, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x16, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x17, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x19, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x25, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x08, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x29, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 7,
            link_layer_type: LinkLayerType::Ether,
            flags: vec![LinkFlag::Broadcast, LinkFlag::Multicast],
            change_mask: vec![],
        },
        attributes: vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(InfoPortData::BridgePort(vec![
                InfoBridgePort::State(BridgePortState::Disabled),
                InfoBridgePort::Priority(32),
                InfoBridgePort::Cost(2),
                InfoBridgePort::HairpinMode(false),
                InfoBridgePort::Guard(false),
                InfoBridgePort::Protect(false),
                InfoBridgePort::FastLeave(false),
                InfoBridgePort::MulticastToUnicast(false),
                InfoBridgePort::Learning(true),
                InfoBridgePort::UnicastFlood(true),
                InfoBridgePort::MulticastFlood(true),
                InfoBridgePort::BroadcastFlood(true),
                InfoBridgePort::ProxyARP(false),
                InfoBridgePort::ProxyARPWifi(false),
                InfoBridgePort::RootId(BridgeId {
                    priority: 0x8000,
                    address: [0x52, 0x54, 0x00, 0xde, 0x0d, 0x2e],
                }),
                InfoBridgePort::BridgeId(BridgeId {
                    priority: 0x8000,
                    address: [0x52, 0x54, 0x00, 0xde, 0x0d, 0x2e],
                }),
                InfoBridgePort::DesignatedPort(32769),
                InfoBridgePort::DesignatedCost(0),
                InfoBridgePort::PortId(32769),
                InfoBridgePort::PortNumber(1),
                InfoBridgePort::TopologyChangeAck(false),
                InfoBridgePort::ConfigPending(false),
                InfoBridgePort::VlanTunnel(false),
                InfoBridgePort::GroupFwdMask(0),
                InfoBridgePort::NeighSupress(false),
                InfoBridgePort::MrpRingOpen(false),
                InfoBridgePort::MrpInOpen(false),
                InfoBridgePort::Isolated(false),
                InfoBridgePort::Locked(false),
                InfoBridgePort::Mab(false),
                InfoBridgePort::MessageAgeTimer(0),
                InfoBridgePort::ForwardDelayTimer(0),
                InfoBridgePort::HoldTimer(0),
                InfoBridgePort::MulticastRouter(
                    BridgePortMulticastRouter::TempQuery,
                ),
                InfoBridgePort::MulticastEhtHostsLimit(512),
                InfoBridgePort::MulticastEhtHostsCnt(0),
                InfoBridgePort::MulticastNGroups(0),
                InfoBridgePort::MulticastMaxGroups(0),
            ])),
        ])],
    };

    assert_eq!(
        expected,
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
