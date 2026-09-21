//! Wire decoding for Control Plane editions (CORD-04 §1, CORD-01 Encoding).
//!
//! Turns a kind-3308 rumor, exactly as carried inside a plaintext seal, into
//! an [`Edition`]. The rumor's `content` is kept byte-verbatim: it is what the
//! edition hash covers, so it is never re-serialised.

use std::fmt::Write as _;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::edition::{Edition, Vac};
use crate::stream::is_hex32;

pub const KIND_CONTROL_EDITION: u64 = 3308;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    NotJson,
    WrongKind,
    /// The rumor's author differs from the seal's (NIP-59 impersonation check).
    AuthorMismatch,
    MissingTag(&'static str),
    /// A tag value breaks CORD-01 Encoding (uppercase hex, leading zeros, ...).
    MalformedTag(&'static str),
}

pub(crate) fn tag_values<'a>(tags: &'a [Value], name: &str) -> Option<Vec<&'a str>> {
    let tag = tags
        .iter()
        .filter_map(Value::as_array)
        .find(|tag| tag.first().and_then(Value::as_str) == Some(name))?;
    tag.iter().skip(1).map(Value::as_str).collect()
}

/// A number tag is its decimal form with no leading zeros and no sign.
pub(crate) fn decimal_u64(text: &str) -> Option<u64> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Decodes a kind-3308 rumor. `seal_pubkey` is the proven author.
///
/// # Errors
///
/// Returns [`WireError`] for a rumor that is not a well-formed edition.
pub fn parse_edition_rumor(seal_pubkey: &str, rumor_json: &str) -> Result<Edition, WireError> {
    let rumor: Value = serde_json::from_str(rumor_json).map_err(|_| WireError::NotJson)?;
    if rumor.get("kind").and_then(Value::as_u64) != Some(KIND_CONTROL_EDITION) {
        return Err(WireError::WrongKind);
    }
    let author = rumor.get("pubkey").and_then(Value::as_str);
    if author != Some(seal_pubkey) {
        return Err(WireError::AuthorMismatch);
    }
    let content = rumor
        .get("content")
        .and_then(Value::as_str)
        .ok_or(WireError::MissingTag("content"))?;
    let tags = rumor
        .get("tags")
        .and_then(Value::as_array)
        .ok_or(WireError::MissingTag("tags"))?;
    let single = |name: &'static str| -> Result<&str, WireError> {
        match tag_values(tags, name).as_deref() {
            Some([value]) => Ok(value),
            Some(_) => Err(WireError::MalformedTag(name)),
            None => Err(WireError::MissingTag(name)),
        }
    };
    let vsk = decimal_u64(single("vsk")?)
        .and_then(|v| u8::try_from(v).ok())
        .ok_or(WireError::MalformedTag("vsk"))?;
    let entity_id = single("eid")?;
    if !is_hex32(entity_id) {
        return Err(WireError::MalformedTag("eid"));
    }
    let version = decimal_u64(single("ev")?)
        .filter(|v| *v >= 1)
        .ok_or(WireError::MalformedTag("ev"))?;
    let prev = match tag_values(tags, "ep").as_deref() {
        None => None,
        Some([prev]) if is_hex32(prev) => Some((*prev).to_owned()),
        Some(_) => return Err(WireError::MalformedTag("ep")),
    };
    let vac = match tag_values(tags, "vac").as_deref() {
        None => None,
        Some([eid, version, hash]) if is_hex32(eid) && is_hex32(hash) => Some(Vac {
            grant_eid: (*eid).to_owned(),
            version: decimal_u64(version).ok_or(WireError::MalformedTag("vac"))?,
            hash: (*hash).to_owned(),
        }),
        Some(_) => return Err(WireError::MalformedTag("vac")),
    };
    Ok(Edition {
        vsk,
        entity_id: entity_id.to_owned(),
        version,
        prev,
        content: content.to_owned(),
        actor: seal_pubkey.to_owned(),
        rumor_id: rumor_id(rumor_json).ok_or(WireError::NotJson)?,
        vac,
    })
}

/// NIP-01 event id of a rumor: sha256 of the canonical
/// `[0, pubkey, created_at, kind, tags, content]` array. An embedded `id` is
/// never trusted.
#[must_use]
pub fn rumor_id(rumor_json: &str) -> Option<String> {
    let rumor: Value = serde_json::from_str(rumor_json).ok()?;
    let preimage = serde_json::to_string(&Value::Array(vec![
        Value::from(0),
        rumor.get("pubkey")?.clone(),
        rumor.get("created_at")?.clone(),
        rumor.get("kind")?.clone(),
        rumor.get("tags")?.clone(),
        rumor.get("content")?.clone(),
    ]))
    .ok()?;
    Some(
        Sha256::digest(preimage.as_bytes())
            .iter()
            .fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{parse_banlist, parse_grant, parse_role};
    use crate::community::{parse_channel_metadata, parse_community_metadata};

    const EXAMPLES: &str = include_str!("../../../docs/cord/examples.md");

    fn hex(byte: &str) -> String {
        byte.repeat(32)
    }

    fn rumor(tags: &str, content: &str) -> String {
        format!(
            r#"{{"kind":3308,"pubkey":"{}","content":{},"tags":{tags},"created_at":1686840217}}"#,
            hex("aa"),
            serde_json::to_string(content).unwrap()
        )
    }

    /// First jsonc code block under `heading`, with line comments removed and
    /// angle-bracket placeholders given concrete values.
    fn example(heading: &str, placeholders: &[(&str, String)]) -> String {
        let section = EXAMPLES
            .split(heading)
            .nth(1)
            .unwrap_or_else(|| panic!("missing {heading}"));
        let block = section
            .split("```jsonc\n")
            .nth(1)
            .and_then(|rest| rest.split("```").next())
            .expect("jsonc block");
        let mut text = block
            .lines()
            .map(|line| line.find(" //").map_or(line, |i| &line[..i]))
            .collect::<Vec<_>>()
            .join("\n");
        for (name, value) in placeholders {
            text = text.replace(name, value);
        }
        text
    }

    #[test]
    fn decodes_a_first_and_a_chained_edition_with_a_citation() {
        let first = rumor(
            &format!(r#"[["vsk","2"],["eid","{}"],["ev","1"]]"#, hex("11")),
            "{}",
        );
        let e1 = parse_edition_rumor(&hex("aa"), &first).unwrap();
        assert_eq!(
            (e1.vsk, e1.version, e1.prev.clone(), e1.vac.clone()),
            (2, 1, None, None)
        );

        let chained = rumor(
            &format!(
                r#"[["vsk","2"],["eid","{}"],["ev","2"],["ep","{}"],["vac","{}","3","{}"]]"#,
                hex("11"),
                e1.hash().unwrap(),
                hex("22"),
                hex("33")
            ),
            "{}",
        );
        let e2 = parse_edition_rumor(&hex("aa"), &chained).unwrap();
        assert_eq!(e2.prev, e1.hash());
        assert_eq!(e2.vac.as_ref().map(|v| v.version), Some(3));
        assert_eq!(e2.rumor_id.len(), 64);
        assert_ne!(e1.rumor_id, e2.rumor_id);
    }

    #[test]
    fn rejects_bad_encoding_and_impersonation() {
        let ok_tags = format!(r#"[["vsk","2"],["eid","{}"],["ev","1"]]"#, hex("11"));
        let good = rumor(&ok_tags, "{}");
        assert_eq!(
            parse_edition_rumor(&hex("bb"), &good),
            Err(WireError::AuthorMismatch)
        );
        let cases = [
            (r#"[["vsk","2"],["eid","{E}"],["ev","01"]]"#, "ev"),
            (r#"[["vsk","2"],["eid","{E}"],["ev","0"]]"#, "ev"),
            (r#"[["vsk","2"],["eid","{U}"],["ev","1"]]"#, "eid"),
            (
                r#"[["vsk","2"],["eid","{E}"],["ev","1"],["ep","zz"]]"#,
                "ep",
            ),
            (
                r#"[["vsk","2"],["eid","{E}"],["ev","1"],["vac","{E}","1"]]"#,
                "vac",
            ),
        ];
        for (tags, tag) in cases {
            let tags = tags.replace("{E}", &hex("11")).replace("{U}", &hex("AB"));
            assert_eq!(
                parse_edition_rumor(&hex("aa"), &rumor(&tags, "{}")),
                Err(WireError::MalformedTag(tag)),
                "{tags}"
            );
        }
        let no_eid = rumor(r#"[["vsk","2"],["ev","1"]]"#, "{}");
        assert_eq!(
            parse_edition_rumor(&hex("aa"), &no_eid),
            Err(WireError::MissingTag("eid"))
        );
        let wrong_kind = good.replace("3308", "9");
        assert_eq!(
            parse_edition_rumor(&hex("aa"), &wrong_kind),
            Err(WireError::WrongKind)
        );
    }

    #[test]
    fn content_bytes_reach_the_hash_verbatim() {
        let spaced = rumor(
            &format!(r#"[["vsk","2"],["eid","{}"],["ev","1"]]"#, hex("11")),
            r#"{ "name": "a" }"#,
        );
        let compact = spaced.replace(r#"{ \"name\": \"a\" }"#, r#"{\"name\":\"a\"}"#);
        let a = parse_edition_rumor(&hex("aa"), &spaced).unwrap();
        let b = parse_edition_rumor(&hex("aa"), &compact).unwrap();
        assert_eq!(a.content, r#"{ "name": "a" }"#);
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn documented_example_payloads_parse_with_our_readers() {
        let meta = example("### vsk 0", &[]);
        let meta: Value = serde_json::from_str(&meta).expect("vsk 0 example is valid JSON");
        let meta = parse_community_metadata(&meta.to_string()).expect("vsk 0");
        assert_eq!(meta.name, "Vector");
        assert_eq!(meta.relays.len(), 2);

        let role = example("### vsk 1", &[("<role_id hex>", hex("44"))]);
        let role = parse_role(&role).expect("vsk 1 role");
        assert_eq!((role.position, role.permissions), (2, 40));
        assert!(role.server_scope);

        // The block lists two objects on separate lines; the first is "general".
        let channel = example("### vsk 2", &[]);
        let channel = channel.lines().next().expect("first line").to_owned();
        let (channel, deleted) = parse_channel_metadata(&hex("55"), &channel).expect("vsk 2");
        assert_eq!(
            (channel.name.as_str(), channel.private, deleted),
            ("general", false, false)
        );

        let grant = example(
            "### vsk 3",
            &[("<member pubkey>", hex("66")), ("<role_id hex>", hex("44"))],
        );
        let (member, roles) = parse_grant(&grant).expect("vsk 3");
        assert_eq!((member, roles.len()), (hex("66"), 2));

        let ban = example("### vsk 4", &[("<banned pubkey>", hex("77"))]);
        assert_eq!(parse_banlist(&ban).expect("vsk 4").len(), 1);
    }
}
