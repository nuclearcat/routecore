#![cfg(feature = "mrt")]

use mrtgen::{
    FatalKind, GeneratorConfig, RouteFormat, generate, generate_from_routes,
    routes_from_json,
};
use routecore::bgp::message::Message as BgpMessage;
use routecore::bgp::types::AfiSafiType;
use routecore::mrt::{Bgp4Mp, MrtFile};

const ROUTES: &str = r#"[
    {
        "prefix": "192.0.2.0/24",
        "nexthop": "198.51.100.1",
        "as_path": [64500, 64496],
        "med": 50,
        "local_pref": 150,
        "standard_communities": ["64500:100", "no-export"],
        "extended_communities": ["rt:64500:200"],
        "large_communities": ["64500:300:400"]
    },
    {
        "prefix": "2001:db8:100::/48",
        "nexthop": "2001:db8::1",
        "as_path": [64501, 4200000001],
        "origin": "incomplete"
    }
]"#;

fn generated_routes(format: RouteFormat) -> mrtgen::generator::Corpus {
    let routes = routes_from_json(ROUTES).expect("route specification is valid");
    generate_from_routes(&routes, format, 1_700_000_000)
        .expect("route corpus generation succeeds")
}

#[test]
fn walks_every_framed_record_in_the_full_corpus() {
    let corpus = generate(&GeneratorConfig::default());
    let file = MrtFile::new(&corpus.bytes);
    let records = file.records().collect::<Result<Vec<_>, _>>()
        .expect("valid and skip-class records retain honest framing");

    assert_eq!(records.len(), corpus.manifest.records.len());
    for (parsed, expected) in records.iter().zip(&corpus.manifest.records) {
        assert_eq!(parsed.timestamp(), expected.timestamp);
        assert_eq!(parsed.length() as u64 + 12, expected.size);
    }
}

#[test]
fn rejects_each_abort_class_tail_without_panicking() {
    for fatal in FatalKind::ALL {
        let corpus = generate(&GeneratorConfig {
            include_valid: false,
            include_skip: false,
            include_combo: false,
            include_attr_errors: false,
            fatal: Some(fatal),
            ..GeneratorConfig::default()
        });
        let file = MrtFile::new(&corpus.bytes);
        let mut records = file.records();

        assert!(records.next().expect("fatal record is reported").is_err());
        assert!(records.next().is_none(), "iterator must fuse after {fatal:?}");
    }
}

#[test]
fn parses_generated_table_dump_v2_routes() {
    let corpus = generated_routes(RouteFormat::TableDumpV2);
    let file = MrtFile::new(&corpus.bytes);

    assert_eq!(file.pi().expect("peer index parses").len(), 2);
    let entries = file.rib_entries().expect("RIB iterator starts")
        .collect::<Result<Vec<_>, _>>()
        .expect("RIB entries parse");
    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0].0, AfiSafiType::Ipv4Unicast);
    assert_eq!(entries[0].3.to_string(), "192.0.2.0/24");
    assert_eq!(entries[0].2.asn.into_u32(), 64500);
    assert!(!entries[0].4.is_empty());

    assert_eq!(entries[1].0, AfiSafiType::Ipv6Unicast);
    assert_eq!(entries[1].3.to_string(), "2001:db8:100::/48");
    assert_eq!(entries[1].2.asn.into_u32(), 64500);
    assert!(!entries[1].4.is_empty());
}

#[test]
fn malformed_rib_entry_is_reported_and_fuses() {
    let mut bytes = generated_routes(RouteFormat::TableDumpV2).bytes;
    bytes.pop();
    let file = MrtFile::new(&bytes);
    let mut entries = file.rib_entries().expect("peer index parses");

    assert!(entries.next().expect("first route is present").is_ok());
    assert!(entries.next().expect("truncated route is reported").is_err());
    assert!(entries.next().is_none());
}

#[test]
fn parses_generated_bgp4mp_updates_and_attributes() {
    let corpus = generated_routes(RouteFormat::Bgp4mp);
    let file = MrtFile::new(&corpus.bytes);
    let messages = file.messages().collect::<Vec<_>>();

    assert_eq!(messages.len(), 2);
    for message in messages {
        let Bgp4Mp::MessageAs4(message) = message else {
            panic!("route-list mode must generate BGP4MP_MESSAGE_AS4");
        };
        let BgpMessage::Update(update) = message.bgp_msg()
            .expect("embedded BGP message parses") else {
            panic!("route-list record must contain an UPDATE");
        };

        assert_eq!(update.announcements_vec().unwrap().len(), 1);
        assert!(update.aspath().unwrap().is_some());
    }

    let Bgp4Mp::MessageAs4(first) = &file.messages().next().unwrap() else {
        unreachable!();
    };
    let BgpMessage::Update(update) = first.bgp_msg().unwrap() else {
        unreachable!();
    };
    assert_eq!(update.multi_exit_disc().unwrap().unwrap().0, 50);
    assert_eq!(update.local_pref().unwrap().unwrap().0, 150);
    assert_eq!(update.communities().unwrap().unwrap().count(), 2);
    assert_eq!(update.ext_communities().unwrap().unwrap().count(), 1);
    assert_eq!(update.large_communities().unwrap().unwrap().count(), 1);
}
