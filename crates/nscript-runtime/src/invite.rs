//! CORD-05 invites: bundle validation, link fragment codec, Invite List
//! merge, Registry fold and Direct Invites, as pure logic.
//!
//! Fetching, NIP-44 bundle decryption and NIP-59 wrapping are host concerns.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::authority::{Roster, community_id, hkdf32, perm};
use crate::stream::is_hex32;
use crate::wire::tag_values;

pub const KIND_DIRECT_INVITE: u64 = 3313;
pub const KIND_INVITE_BUNDLE: u64 = 33301;
/// Link format byte; also selects the relay dictionary generation.
pub const FRAGMENT_VERSION: u8 = 4;
/// Most channels a bundle may carry before it is refused unallocated.
pub const MAX_CHANNELS: usize = 256;
/// Community relay cap a bundle's list is truncated to (CORD-02 §6).
pub const MAX_RELAYS: usize = 5;
/// Bootstrap relays a fragment may carry explicitly.
pub const MAX_FRAGMENT_RELAYS: usize = 3;

/// The stock relay dictionary (ids 1..=4).
pub const RELAY_DICTIONARY: [&str; 4] = [
    "wss://jskitty.com/nostr",
    "wss://asia.vectorapp.io/nostr",
    "wss://relay.ditto.pub",
    "wss://relay.dreamith.to",
];

/// Assumed position of the "stock relay set" flag: the spec names the flag
/// but not its bit. Confirm against a reference implementation before
/// interoperating.
const FLAG_STOCK_RELAYS: u8 = 0b0000_0001;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InviteError {
    Malformed(&'static str),
    /// `owner` and `owner_salt` do not reproduce the `community_id`.
    OwnerMismatch,
    TooManyChannels,
    Expired,
}

#[derive(Clone, Eq, PartialEq)]
pub struct InviteChannel {
    pub id: String,
    pub key: String,
    pub epoch: u64,
    pub name: String,
}

/// A validated `CommunityInvite`. Keys are private to keep them out of debug
/// output; use the accessors deliberately.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityInvite {
    pub community_id: String,
    pub owner: String,
    pub owner_salt: String,
    community_root: String,
    pub root_epoch: u64,
    /// Absent means a legacy, pre-split Community (CORD-06 §3).
    pub control_pk: Option<String>,
    pub channels: Vec<InviteChannel>,
    pub relays: Vec<String>,
    pub name: String,
    /// Unix milliseconds; past it the preview renders but joining refuses.
    pub expires_at: Option<u64>,
    pub creator_npub: Option<String>,
    pub label: Option<String>,
}

impl std::fmt::Debug for CommunityInvite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommunityInvite")
            .field("community_id", &self.community_id)
            .field("name", &self.name)
            .field("channels", &self.channels.len())
            .finish_non_exhaustive()
    }
}

impl CommunityInvite {
    /// The base access key. Handle as key material.
    #[must_use]
    pub fn community_root(&self) -> &str {
        &self.community_root
    }

    /// Whether joining is still allowed at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`InviteError::Expired`] past `expires_at`.
    pub fn check_joinable(&self, now_ms: u64) -> Result<(), InviteError> {
        match self.expires_at {
            Some(at) if now_ms >= at => Err(InviteError::Expired),
            _ => Ok(()),
        }
    }
}

fn text<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, InviteError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(InviteError::Malformed(field))
}

fn hex_field(value: &Value, field: &'static str) -> Result<String, InviteError> {
    let found = text(value, field)?;
    if is_hex32(found) {
        Ok(found.to_owned())
    } else {
        Err(InviteError::Malformed(field))
    }
}

/// Parses and validates a bundle (fetched or from a Direct Invite). The
/// bundle is attacker-crafted, so it is bounded before anything is allocated
/// per entry, and the owner is verified against the self-certifying id.
///
/// # Errors
///
/// Returns [`InviteError`] for malformed, oversize or owner-forging bundles.
pub fn parse_invite(json: &str) -> Result<CommunityInvite, InviteError> {
    let value: Value = serde_json::from_str(json).map_err(|_| InviteError::Malformed("json"))?;
    let raw_channels = value
        .get("channels")
        .and_then(Value::as_array)
        .ok_or(InviteError::Malformed("channels"))?;
    if raw_channels.len() > MAX_CHANNELS {
        return Err(InviteError::TooManyChannels);
    }
    let community = hex_field(&value, "community_id")?;
    let owner = hex_field(&value, "owner")?;
    let owner_salt = hex_field(&value, "owner_salt")?;
    if community_id(&owner, &owner_salt).as_deref() != Some(community.as_str()) {
        return Err(InviteError::OwnerMismatch);
    }
    let channels = raw_channels
        .iter()
        .map(|channel| {
            Ok(InviteChannel {
                id: hex_field(channel, "id")?,
                key: hex_field(channel, "key")?,
                epoch: channel
                    .get("epoch")
                    .and_then(Value::as_u64)
                    .ok_or(InviteError::Malformed("epoch"))?,
                name: text(channel, "name")?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, InviteError>>()?;
    // Truncate rather than trust: an unbounded list is a connect-storm vector.
    let relays = value
        .get("relays")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .take(MAX_RELAYS)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let optional =
        |field: &'static str| value.get(field).and_then(Value::as_str).map(str::to_owned);
    let control_pk = match value.get("control_pk") {
        None | Some(Value::Null) => None,
        Some(_) => Some(hex_field(&value, "control_pk")?),
    };
    Ok(CommunityInvite {
        community_id: community,
        owner,
        owner_salt,
        community_root: hex_field(&value, "community_root")?,
        root_epoch: value
            .get("root_epoch")
            .and_then(Value::as_u64)
            .ok_or(InviteError::Malformed("root_epoch"))?,
        control_pk,
        channels,
        relays,
        name: text(&value, "name")?.to_owned(),
        expires_at: value.get("expires_at").and_then(Value::as_u64),
        creator_npub: optional("creator_npub"),
        label: optional("label"),
    })
}

/// `bundle_key = hkdf(token, "concord/invite-key")` (CORD-02 A.6: id all
/// zeroes, no epoch). The token is the only thing that opens a bundle.
#[must_use]
pub fn bundle_key(token: &[u8; 16]) -> [u8; 32] {
    let mut info = b"concord/invite-key".to_vec();
    info.push(0);
    info.extend_from_slice(&[0_u8; 32]);
    hkdf32(token, &info)
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(BASE64URL[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0_u32;
    let mut bits = 0;
    for ch in text.bytes() {
        let value = u32::try_from(BASE64URL.iter().position(|b| *b == ch)?).ok()?;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    // Canonical only: leftover bits must be zero padding.
    (acc & ((1 << bits) - 1) == 0).then_some(out)
}

/// A decoded link fragment.
#[derive(Clone, Eq, PartialEq)]
pub struct Fragment {
    pub token: [u8; 16],
    pub relays: Vec<String>,
}

impl std::fmt::Debug for Fragment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token unlocks the bundle: never print it.
        formatter
            .debug_struct("Fragment")
            .field("relays", &self.relays)
            .finish_non_exhaustive()
    }
}

/// Encodes `[version][flags][relays?][token:16]` as base64url without padding.
/// The four dictionary primaries encode as the stock flag; anything else is an
/// explicit list of at most three relays.
///
/// # Errors
///
/// Returns [`InviteError`] for too many relays or an unencodable relay.
pub fn encode_fragment(token: &[u8; 16], relays: &[String]) -> Result<String, InviteError> {
    let mut bytes = vec![FRAGMENT_VERSION];
    if relays.iter().map(String::as_str).eq(RELAY_DICTIONARY) {
        bytes.push(FLAG_STOCK_RELAYS);
    } else {
        if relays.len() > MAX_FRAGMENT_RELAYS {
            return Err(InviteError::Malformed("relays"));
        }
        bytes.push(0);
        bytes.push(u8::try_from(relays.len()).map_err(|_| InviteError::Malformed("relays"))?);
        for relay in relays {
            if let Some(id) = RELAY_DICTIONARY.iter().position(|known| known == relay) {
                bytes.push(u8::try_from(id + 1).map_err(|_| InviteError::Malformed("relays"))?);
                continue;
            }
            let (marker, body) = relay
                .strip_prefix("wss://")
                .map_or((255_u8, relay.as_str()), |host| (0, host));
            bytes.push(marker);
            bytes.push(u8::try_from(body.len()).map_err(|_| InviteError::Malformed("relays"))?);
            bytes.extend_from_slice(body.as_bytes());
        }
    }
    bytes.extend_from_slice(token);
    Ok(base64url_encode(&bytes))
}

/// Decodes a link fragment. Versions below the current one are refused as
/// legacy rather than decoded against the wrong dictionary.
///
/// # Errors
///
/// Returns [`InviteError::Malformed`] for any structural problem.
pub fn decode_fragment(fragment: &str) -> Result<Fragment, InviteError> {
    let bad = InviteError::Malformed("fragment");
    let bytes = base64url_decode(fragment).ok_or(bad.clone())?;
    let (&version, rest) = bytes.split_first().ok_or(bad.clone())?;
    if version < FRAGMENT_VERSION {
        return Err(InviteError::Malformed("legacy link"));
    }
    let (&flags, mut rest) = rest.split_first().ok_or(bad.clone())?;
    let mut relays = Vec::new();
    if flags & FLAG_STOCK_RELAYS != 0 {
        relays.extend(RELAY_DICTIONARY.iter().map(|r| (*r).to_owned()));
    } else {
        let (&count, tail) = rest.split_first().ok_or(bad.clone())?;
        rest = tail;
        if usize::from(count) > MAX_FRAGMENT_RELAYS {
            return Err(bad);
        }
        for _ in 0..count {
            let (&marker, tail) = rest.split_first().ok_or(bad.clone())?;
            rest = tail;
            if (1..=254).contains(&marker) {
                let relay = RELAY_DICTIONARY
                    .get(usize::from(marker) - 1)
                    .ok_or(bad.clone())?;
                relays.push((*relay).to_owned());
                continue;
            }
            let (&len, tail) = rest.split_first().ok_or(bad.clone())?;
            let (body, tail) = tail.split_at_checked(usize::from(len)).ok_or(bad.clone())?;
            rest = tail;
            let body = std::str::from_utf8(body).map_err(|_| bad.clone())?;
            relays.push(if marker == 0 {
                format!("wss://{body}")
            } else {
                body.to_owned()
            });
        }
    }
    let token: [u8; 16] = rest.try_into().map_err(|_| bad)?;
    Ok(Fragment { token, relays })
}

/// A creator's private Invite List (kind 13303). Two copies merge without
/// coordination: the token is the merge key, entries are immutable once
/// minted, tombstones union, and a tombstone beats an entry terminally.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InviteList {
    entries: BTreeMap<String, Value>,
    tombstones: BTreeSet<(String, String)>,
    /// Unknown top-level fields, preserved for round-tripping.
    extra: Map<String, Value>,
}

impl InviteList {
    /// Parses a decrypted Invite List document.
    ///
    /// # Errors
    ///
    /// Returns [`InviteError::Malformed`] for a structurally invalid document.
    pub fn parse(json: &str) -> Result<Self, InviteError> {
        let Value::Object(mut document) =
            serde_json::from_str(json).map_err(|_| InviteError::Malformed("json"))?
        else {
            return Err(InviteError::Malformed("json"));
        };
        let mut list = Self::default();
        for entry in document
            .remove("entries")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
        {
            let token = entry
                .get("token")
                .and_then(Value::as_str)
                .ok_or(InviteError::Malformed("token"))?;
            list.entries.insert(token.to_owned(), entry);
        }
        for grave in document
            .remove("tombstones")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
        {
            let token = grave
                .get("token")
                .and_then(Value::as_str)
                .ok_or(InviteError::Malformed("token"))?;
            let community = grave
                .get("community_id")
                .and_then(Value::as_str)
                .ok_or(InviteError::Malformed("community_id"))?;
            list.tombstones
                .insert((token.to_owned(), community.to_owned()));
        }
        list.extra = document;
        list.settle();
        Ok(list)
    }

    fn settle(&mut self) {
        let dead: BTreeSet<&String> = self.tombstones.iter().map(|(token, _)| token).collect();
        self.entries.retain(|token, _| !dead.contains(token));
    }

    /// Merges another device's copy. Existing entries win (immutable once
    /// minted); a tombstone from either side removes the entry for good.
    pub fn merge(&mut self, other: &Self) {
        for (token, entry) in &other.entries {
            self.entries
                .entry(token.clone())
                .or_insert_with(|| entry.clone());
        }
        self.tombstones.extend(other.tombstones.iter().cloned());
        for (key, value) in &other.extra {
            self.extra
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
        self.settle();
    }

    /// Retires a link, terminally.
    pub fn revoke(&mut self, token: &str, community_id: &str) {
        self.tombstones
            .insert((token.to_owned(), community_id.to_owned()));
        self.settle();
    }

    /// Live link tokens.
    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Serialises the document, preserving unknown fields and entry contents.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut document = self.extra.clone();
        document.insert(
            "entries".into(),
            Value::Array(self.entries.values().cloned().collect()),
        );
        document.insert(
            "tombstones".into(),
            Value::Array(
                self.tombstones
                    .iter()
                    .map(|(token, community)| serde_json::json!({"token": token, "community_id": community}))
                    .collect(),
            ),
        );
        Value::Object(document).to_string()
    }
}

/// Folds every creator's Registry into one active set of link-signer pubkeys.
/// A Registry is honoured only while its author holds `CREATE_INVITE`.
#[must_use]
pub fn active_links(registries: &[(String, Vec<String>)], roster: &Roster) -> BTreeSet<String> {
    registries
        .iter()
        .filter(|(author, _)| {
            *author == roster.owner
                || (!roster.banned.contains(author)
                    && roster.permissions(author) & perm::CREATE_INVITE != 0)
        })
        .flat_map(|(_, signers)| signers.iter().filter(|s| is_hex32(s)).cloned())
        .collect()
}

/// A Community is Public exactly when a live link exists.
#[must_use]
pub fn is_public(active: &BTreeSet<String>) -> bool {
    !active.is_empty()
}

/// Retiring the last live link flips a Community back to Private, which
/// requires a Refounding (CORD-06).
#[must_use]
pub fn requires_refounding(before: &BTreeSet<String>, after: &BTreeSet<String>) -> bool {
    is_public(before) && !is_public(after)
}

/// Decodes a Direct Invite rumor (kind 3313). The seal's verified npub is the
/// inviter; the rumor's author must match it.
///
/// # Errors
///
/// Returns [`InviteError`] for a wrong kind, impersonation, or a bad bundle.
pub fn parse_direct_invite(
    seal_pubkey: &str,
    rumor_json: &str,
) -> Result<CommunityInvite, InviteError> {
    let rumor: Value =
        serde_json::from_str(rumor_json).map_err(|_| InviteError::Malformed("json"))?;
    if rumor.get("kind").and_then(Value::as_u64) != Some(KIND_DIRECT_INVITE) {
        return Err(InviteError::Malformed("kind"));
    }
    if rumor.get("pubkey").and_then(Value::as_str) != Some(seal_pubkey) {
        return Err(InviteError::Malformed("pubkey"));
    }
    parse_invite(text(&rumor, "content")?)
}

/// The relay filter that indexes a recipient's Direct Invites.
#[must_use]
pub fn direct_invite_filter(recipient: &str) -> Value {
    serde_json::json!({"kinds": [1059], "#p": [recipient], "#k": ["3313"]})
}

/// Whether a wrap's outer tags hint at a Direct Invite. The tag is an
/// unsigned relay-visible hint, never authority: an invite is whatever
/// unwraps to a kind 3313 rumor.
#[must_use]
pub fn wrap_hints_direct_invite(outer_tags: &[Value]) -> bool {
    tag_values(outer_tags, "k").is_some_and(|v| v == [KIND_DIRECT_INVITE.to_string().as_str()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Role;
    use serde_json::json;

    const OWNER: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SALT: &str = "0202020202020202020202020202020202020202020202020202020202020202";
    const ROOT: &str = "0909090909090909090909090909090909090909090909090909090909090909";

    fn bundle(mutate: impl FnOnce(&mut Value)) -> String {
        let mut value = json!({
            "community_id": community_id(OWNER, SALT).unwrap(),
            "owner": OWNER, "owner_salt": SALT,
            "community_root": ROOT, "root_epoch": 3,
            "control_pk": "0303030303030303030303030303030303030303030303030303030303030303",
            "channels": [{"id": "cc".repeat(32), "key": "dd".repeat(32), "epoch": 1, "name": "general"}],
            "relays": ["wss://a", "wss://b"],
            "name": "Vector", "label": "Conf 2026", "expires_at": 5000
        });
        mutate(&mut value);
        value.to_string()
    }

    #[test]
    fn bundles_self_certify_the_owner_and_are_bounded() {
        let invite = parse_invite(&bundle(|_| {})).unwrap();
        assert_eq!(invite.name, "Vector");
        assert_eq!(invite.label.as_deref(), Some("Conf 2026"));
        assert_eq!(invite.community_root(), ROOT);
        assert!(
            !format!("{invite:?}").contains(ROOT),
            "keys stay out of debug"
        );

        // A false owner cannot be smuggled onto a real community id.
        let forged = bundle(|v| v["owner"] = json!("aa".repeat(32)));
        assert_eq!(parse_invite(&forged), Err(InviteError::OwnerMismatch));
        let wrong_salt = bundle(|v| v["owner_salt"] = json!("bb".repeat(32)));
        assert_eq!(parse_invite(&wrong_salt), Err(InviteError::OwnerMismatch));

        let many = bundle(|v| {
            v["channels"] = Value::Array(vec![v["channels"][0].clone(); MAX_CHANNELS + 1]);
        });
        assert_eq!(parse_invite(&many), Err(InviteError::TooManyChannels));
        let relays = bundle(|v| {
            v["relays"] = json!((0..50).map(|i| format!("wss://r{i}")).collect::<Vec<_>>());
        });
        assert_eq!(parse_invite(&relays).unwrap().relays.len(), MAX_RELAYS);
        assert!(parse_invite(&bundle(|v| v["community_root"] = json!("short"))).is_err());
    }

    #[test]
    fn legacy_communities_omit_control_pk_and_expiry_gates_joining_only() {
        let legacy = parse_invite(&bundle(|v| {
            v.as_object_mut().unwrap().remove("control_pk");
        }))
        .unwrap();
        assert_eq!(legacy.control_pk, None);
        // Past expiry the preview still parses; joining refuses.
        assert_eq!(legacy.check_joinable(4999), Ok(()));
        assert_eq!(legacy.check_joinable(5000), Err(InviteError::Expired));
        let open_ended = parse_invite(&bundle(|v| {
            v.as_object_mut().unwrap().remove("expires_at");
        }))
        .unwrap();
        assert_eq!(open_ended.check_joinable(u64::MAX), Ok(()));
    }

    #[test]
    fn fragments_round_trip_stock_dictionary_and_literal_relays() {
        let token = [0xAB; 16];
        let stock: Vec<String> = RELAY_DICTIONARY.iter().map(|r| (*r).to_owned()).collect();
        let encoded = encode_fragment(&token, &stock).unwrap();
        // Stock set costs zero relay bytes: version + flags + token = 18 bytes.
        assert_eq!(encoded.len(), 24);
        let decoded = decode_fragment(&encoded).unwrap();
        assert_eq!((decoded.token, decoded.relays), (token, stock));

        let mixed = vec![
            RELAY_DICTIONARY[2].to_owned(),
            "wss://relay.example.com".to_owned(),
            "ws://localhost:7777".to_owned(),
        ];
        let decoded = decode_fragment(&encode_fragment(&token, &mixed).unwrap()).unwrap();
        assert_eq!(decoded.relays, mixed);
        assert!(
            !format!("{decoded:?}").contains("171"),
            "token never printed"
        );

        let none = decode_fragment(&encode_fragment(&token, &[]).unwrap()).unwrap();
        assert!(none.relays.is_empty());
        let four_custom: Vec<String> = (0..4).map(|i| format!("wss://r{i}")).collect();
        assert!(
            encode_fragment(&token, &four_custom).is_err(),
            "max 3 bootstrap relays"
        );
    }

    #[test]
    fn fragment_decoder_rejects_legacy_versions_and_garbage() {
        let token = [1_u8; 16];
        let good = encode_fragment(&token, &[]).unwrap();
        let mut bytes = base64url_decode(&good).unwrap();
        bytes[0] = 3;
        assert_eq!(
            decode_fragment(&base64url_encode(&bytes)),
            Err(InviteError::Malformed("legacy link"))
        );
        assert!(decode_fragment("").is_err());
        assert!(decode_fragment("!!!").is_err());
        // Truncated token, unknown dictionary id, and trailing bytes.
        assert!(decode_fragment(&base64url_encode(&[4, 1, 0, 1, 2, 3])).is_err());
        let mut unknown = vec![4, 0, 1, 200];
        unknown.extend_from_slice(&token);
        assert!(decode_fragment(&base64url_encode(&unknown)).is_err());
        let mut trailing = base64url_decode(&good).unwrap();
        trailing.push(0);
        assert!(decode_fragment(&base64url_encode(&trailing)).is_err());
        // Non-canonical base64 (stray low bits) is refused.
        assert!(base64url_decode("AB").is_none());
    }

    #[test]
    fn bundle_key_depends_only_on_the_token() {
        let a = bundle_key(&[1; 16]);
        assert_eq!(a, bundle_key(&[1; 16]));
        assert_ne!(a, bundle_key(&[2; 16]));
    }

    #[test]
    fn invite_lists_merge_without_coordination_and_tombstones_are_terminal() {
        let entry = |token: &str, label: &str| json!({"token": token, "signer_sk": "s", "community_id": "c", "label": label, "future": 1});
        let doc = |entries: Vec<Value>, tombs: Vec<&str>, extra: Value| {
            json!({"entries": entries, "tombstones": tombs.iter().map(|t| json!({"token": t, "community_id": "c"})).collect::<Vec<_>>(), "x": extra}).to_string()
        };
        let mut a = InviteList::parse(&doc(
            vec![entry("t1", "first"), entry("t2", "two")],
            vec![],
            json!(null),
        ))
        .unwrap();
        let b = InviteList::parse(&doc(
            vec![entry("t1", "changed"), entry("t3", "three")],
            vec!["t2"],
            json!(7),
        ))
        .unwrap();
        a.merge(&b);
        let tokens: Vec<_> = a.tokens().collect();
        assert_eq!(tokens, ["t1", "t3"], "t2 tombstoned by the other device");
        let json = a.to_json();
        assert!(
            json.contains("\"first\"") && !json.contains("changed"),
            "entries are immutable once minted"
        );
        assert!(
            json.contains("\"future\":1"),
            "unknown entry fields survive"
        );
        assert!(json.contains("\"x\":"), "unknown top-level fields survive");

        // A stale device can never resurrect a revoked link.
        let stale = InviteList::parse(&doc(vec![entry("t2", "two")], vec![], json!(null))).unwrap();
        a.merge(&stale);
        assert!(a.tokens().all(|t| t != "t2"));
        a.revoke("t1", "c");
        assert_eq!(a.tokens().collect::<Vec<_>>(), ["t3"]);
        // Merge is order-independent.
        let (mut ab, mut ba) = (InviteList::default(), InviteList::default());
        let x = InviteList::parse(&doc(vec![entry("t1", "x")], vec![], json!(null))).unwrap();
        let y = InviteList::parse(&doc(vec![entry("t9", "y")], vec!["t1"], json!(null))).unwrap();
        ab.merge(&x);
        ab.merge(&y);
        ba.merge(&y);
        ba.merge(&x);
        assert_eq!(
            ab.tokens().collect::<Vec<_>>(),
            ba.tokens().collect::<Vec<_>>()
        );
    }

    #[test]
    fn registry_counts_only_authors_holding_create_invite() {
        let mut roster = Roster::new(OWNER);
        roster.roles.insert(
            "inviter".into(),
            Role {
                role_id: "inviter".into(),
                position: 3,
                permissions: perm::CREATE_INVITE,
                server_scope: true,
            },
        );
        roster.grants.insert("alice".into(), vec!["inviter".into()]);
        let link = |n: u8| format!("{n:02x}").repeat(32);
        let registries = vec![
            ("alice".to_owned(), vec![link(1), "not-hex".to_owned()]),
            ("mallory".to_owned(), vec![link(2)]),
            (OWNER.to_owned(), vec![link(3)]),
        ];
        let active = active_links(&registries, &roster);
        assert_eq!(active, BTreeSet::from([link(1), link(3)]));
        assert!(is_public(&active));
        assert!(!is_public(&BTreeSet::new()));
        // Retiring the last live link flips to Private and needs a Refounding.
        let last = BTreeSet::from([link(1)]);
        assert!(requires_refounding(&last, &BTreeSet::new()));
        assert!(!requires_refounding(&active, &last));
        roster.banned.insert("alice".into());
        assert_eq!(
            active_links(&registries, &roster),
            BTreeSet::from([link(3)])
        );
    }

    #[test]
    fn direct_invites_prove_the_inviter_and_are_indexed_by_kind_tag() {
        let inviter = "aa".repeat(32);
        let rumor = |kind: u64, author: &str| {
            json!({"kind": kind, "pubkey": author, "content": bundle(|_| {}), "tags": []})
                .to_string()
        };
        assert!(parse_direct_invite(&inviter, &rumor(3313, &inviter)).is_ok());
        assert!(
            parse_direct_invite(&inviter, &rumor(3313, &"bb".repeat(32))).is_err(),
            "impersonation"
        );
        assert!(parse_direct_invite(&inviter, &rumor(9, &inviter)).is_err());
        // The bundle validates exactly as a fetched one.
        let forged = json!({"kind": 3313, "pubkey": inviter, "content": bundle(|v| v["owner"] = json!("aa".repeat(32))), "tags": []}).to_string();
        assert_eq!(
            parse_direct_invite(&inviter, &forged),
            Err(InviteError::OwnerMismatch)
        );

        assert_eq!(
            direct_invite_filter("me"),
            json!({"kinds": [1059], "#p": ["me"], "#k": ["3313"]})
        );
        assert!(wrap_hints_direct_invite(
            json!([["p", "me"], ["k", "3313"]]).as_array().unwrap()
        ));
        assert!(!wrap_hints_direct_invite(
            json!([["p", "me"]]).as_array().unwrap()
        ));
    }
}
