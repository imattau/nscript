//! CORD-02/03 community and channel state read from the folded Control Plane.
//!
//! Metadata lives in editions (CORD-04 §1), so this module only interprets an
//! [`EditionFold`]; it holds no state of its own. Epochs are not modelled
//! here: they change only through a Rekey (CORD-06).

use std::collections::BTreeMap;

use crate::edition::{EditionAuthority, EditionFold, VSK_CHANNEL_METADATA, VSK_COMMUNITY_METADATA};

/// Protocol-wide UTF-8 byte cap for community, channel and role names.
pub const NAME_MAX_BYTES: usize = 64;
/// Community description byte cap.
pub const DESCRIPTION_MAX_BYTES: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelMetadata {
    pub channel_id: String,
    pub name: String,
    pub private: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityMetadata {
    pub name: String,
    pub description: Option<String>,
    pub relays: Vec<String>,
}

/// Parses a channel metadata edition's content. Returns `None` for content a
/// reader must ignore (malformed, oversize name). The second value is the
/// terminal `deleted` flag.
#[must_use]
pub fn parse_channel_metadata(channel_id: &str, content: &str) -> Option<(ChannelMetadata, bool)> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    let name = value.get("name")?.as_str()?;
    if name.is_empty() || name.len() > NAME_MAX_BYTES {
        return None;
    }
    let private = value.get("private")?.as_bool()?;
    let deleted = value
        .get("deleted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Some((
        ChannelMetadata {
            channel_id: channel_id.to_owned(),
            name: name.to_owned(),
            private,
        },
        deleted,
    ))
}

/// Parses a community metadata edition's content.
#[must_use]
pub fn parse_community_metadata(content: &str) -> Option<CommunityMetadata> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    let name = value.get("name")?.as_str()?;
    if name.is_empty() || name.len() > NAME_MAX_BYTES {
        return None;
    }
    let description = match value.get("description") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) if text.len() <= DESCRIPTION_MAX_BYTES => {
            Some(text.clone())
        }
        Some(_) => return None,
    };
    let relays = value
        .get("relays")
        .and_then(serde_json::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|relay| relay.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Some(CommunityMetadata {
        name: name.to_owned(),
        description,
        relays,
    })
}

/// Read-only view of community structure over a folded Control Plane.
pub struct CommunityView<'a, A: EditionAuthority> {
    fold: &'a EditionFold<A>,
}

impl<'a, A: EditionAuthority> CommunityView<'a, A> {
    #[must_use]
    pub fn new(fold: &'a EditionFold<A>) -> Self {
        Self { fold }
    }

    /// The community's metadata, addressed by its `community_id`.
    #[must_use]
    pub fn metadata(&self, community_id: &str) -> Option<CommunityMetadata> {
        let head = self.fold.head(community_id)?;
        if head.head.vsk != VSK_COMMUNITY_METADATA {
            return None;
        }
        parse_community_metadata(&head.head.content)
    }

    /// Live channels keyed by `channel_id`. Deleted channels (a terminal
    /// state), channels whose head content must be ignored, and suspended
    /// entities are omitted.
    #[must_use]
    pub fn channels(&self) -> BTreeMap<String, ChannelMetadata> {
        let mut out = BTreeMap::new();
        for id in self.fold.entity_ids() {
            let Some(head) = self.fold.head(id) else {
                continue;
            };
            if head.suspended || head.head.vsk != VSK_CHANNEL_METADATA {
                continue;
            }
            if let Some((meta, false)) = parse_channel_metadata(id, &head.head.content) {
                out.insert(id.to_owned(), meta);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edition::{AllowAll, Edition, FoldMode};

    fn hex(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn edition(
        vsk: u8,
        eid: u8,
        version: u64,
        prev: Option<&Edition>,
        content: &str,
        id: &str,
    ) -> Edition {
        Edition {
            vsk,
            entity_id: hex(eid),
            version,
            prev: prev.map(|p| p.hash().unwrap()),
            content: content.to_owned(),
            actor: "owner".to_owned(),
            rumor_id: id.to_owned(),
        }
    }

    #[test]
    fn channel_lifecycle_folds_regardless_of_arrival_order() {
        let v1 = edition(
            VSK_CHANNEL_METADATA,
            1,
            1,
            None,
            r#"{"name":"chat","private":false}"#,
            "a",
        );
        let v2 = edition(
            VSK_CHANNEL_METADATA,
            1,
            2,
            Some(&v1),
            r#"{"name":"general","private":false}"#,
            "b",
        );
        let mut fold = EditionFold::new(AllowAll, FoldMode::Tracking, 16);
        fold.insert(v2).unwrap();
        fold.insert(v1).unwrap();
        let channels = CommunityView::new(&fold).channels();
        assert_eq!(channels[&hex(1)].name, "general");
        assert!(!channels[&hex(1)].private);
    }

    #[test]
    fn deleted_channels_are_terminal_and_hidden() {
        let v1 = edition(
            VSK_CHANNEL_METADATA,
            1,
            1,
            None,
            r#"{"name":"gone","private":false}"#,
            "a",
        );
        let v2 = edition(
            VSK_CHANNEL_METADATA,
            1,
            2,
            Some(&v1),
            r#"{"name":"gone","private":false,"deleted":true}"#,
            "b",
        );
        let mut fold = EditionFold::new(AllowAll, FoldMode::Tracking, 16);
        fold.insert(v1).unwrap();
        fold.insert(v2).unwrap();
        assert!(CommunityView::new(&fold).channels().is_empty());
    }

    #[test]
    fn oversize_or_malformed_channel_content_is_ignored() {
        let long = "x".repeat(NAME_MAX_BYTES + 1);
        let bad = edition(
            VSK_CHANNEL_METADATA,
            1,
            1,
            None,
            &format!(r#"{{"name":"{long}","private":false}}"#),
            "a",
        );
        let junk = edition(VSK_CHANNEL_METADATA, 2, 1, None, "not json", "b");
        let mut fold = EditionFold::new(AllowAll, FoldMode::Tracking, 16);
        fold.insert(bad).unwrap();
        fold.insert(junk).unwrap();
        assert!(CommunityView::new(&fold).channels().is_empty());
    }

    #[test]
    fn community_metadata_reads_name_description_and_relays() {
        let meta = edition(
            VSK_COMMUNITY_METADATA,
            7,
            1,
            None,
            r#"{"name":"Vector","description":"hi","relays":["wss://a","wss://b"]}"#,
            "a",
        );
        let mut fold = EditionFold::new(AllowAll, FoldMode::Tracking, 16);
        fold.insert(meta).unwrap();
        let view = CommunityView::new(&fold).metadata(&hex(7)).unwrap();
        assert_eq!(view.name, "Vector");
        assert_eq!(view.description.as_deref(), Some("hi"));
        assert_eq!(view.relays.len(), 2);
    }
}
