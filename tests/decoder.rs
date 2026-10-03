use serde_json::Value;
use std::{fs, path::PathBuf};
use winbox_cdb::*;
fn book(msg: &[u8]) -> Vec<u8> {
    let mut out = PLAIN.to_le_bytes().to_vec();
    out.extend((msg.len() as u32).to_le_bytes());
    out.extend(msg);
    out
}
#[test]
fn reference_all_types_and_encryption() {
    for (name, password) in [
        ("plain", None),
        ("encrypted", Some(" passphrase😀 ".as_bytes())),
        ("empty-encrypted", Some(b"".as_slice())),
    ] {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let data = fs::read(root.join(format!("{name}.cdb"))).unwrap();
        let doc = decode_cdb(&data, password).unwrap();
        let expected: Value =
            serde_json::from_slice(&fs::read(root.join(format!("{name}.json"))).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(&doc).unwrap(), expected);
        assert_eq!(
            format_text(&doc).unwrap(),
            fs::read_to_string(root.join(format!("{name}.txt"))).unwrap()
        );
    }
}
#[test]
fn invalid_encryption_and_headers() {
    let enc = include_bytes!("fixtures/encrypted.cdb");
    assert!(decode_cdb(enc, None).is_err());
    assert!(decode_cdb(enc, Some(b"wrong")).is_err());
    for n in 0..40 {
        assert!(decode_cdb(&enc[..n], Some(b"wrong")).is_err());
    }
    assert!(decode_cdb(b"BAD!", None).is_err());
    assert!(decode_cdb(&book(b"bad marker"), None).is_err());
    assert!(decode_cdb(&book(b"M2\x01\x00\x00\x78"), None).is_err());
    assert_eq!(
        decode_cdb(&PLAIN.to_le_bytes(), None).unwrap().record_count,
        0
    );
}
#[test]
fn truncation_and_resource_limits() {
    let valid = book(b"M2\x01\x00\x00\x21\x03abc");
    for n in 0..valid.len() {
        if n != 4 {
            assert!(decode_cdb(&valid[..n], None).is_err(), "prefix {n}");
        }
    }
    let mut too_big = PLAIN.to_le_bytes().to_vec();
    too_big.extend(0x100001u32.to_le_bytes());
    assert!(decode_cdb(&too_big, None).is_err());
    let count = book(b"M2\x01\x00\x00\xa2\xff\xff\xff\xff");
    assert!(decode_cdb(&count, None).is_err());
    let mut nested = b"M2".to_vec();
    for _ in 0..34 {
        let mut next = b"M2".to_vec();
        next.extend(0x2a000001u32.to_le_bytes());
        next.extend((nested.len() as u32).to_le_bytes());
        next.extend(nested);
        nested = next;
    }
    assert!(decode_cdb(&book(&nested), None).is_err());
    assert!(decode_cdb(&vec![0; MAX_FILE + 1], None).is_err());
    let mut records = PLAIN.to_le_bytes().to_vec();
    records.resize(4 + 100_001 * 4, 0);
    assert!(decode_cdb(&records, None).is_err());
}
#[test]
fn private_export_preserves_existing_file_and_password_whitespace() {
    let root = std::env::temp_dir().join(format!("cdb-test-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("out.txt");
    let _ = fs::remove_file(&path);
    write_private(&path, "hello").unwrap();
    assert!(write_private(&path, "replace").is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let pw = root.join("pw");
    fs::write(&pw, b" pass \r\n").unwrap();
    assert_eq!(read_password(&pw).unwrap().as_slice(), b" pass ");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn duplicate_columns_are_not_lost() {
    let doc = decode_cdb(include_bytes!("fixtures/plain.cdb"), None).unwrap();
    assert!(doc.records[0].column("user").contains("guest |"));
    assert_eq!(doc.records[0].column("address"), "192.0.2.1");
}
