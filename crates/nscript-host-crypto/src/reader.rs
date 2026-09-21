//! Reading a Channel: raw wraps in, verified messages out.
//!
//! This is the substance behind `on <stream> { ... }`. A handler must see only
//! what an honest Concord client would show: events that open under the plane
//! key, are bound to this Channel and epoch, have not expired, come from
//! authors who are not banned, and are not duplicates. Everything else is
//! dropped, and the reason is reported so a host can log it.

use std::collections::BTreeSet;

use nscript_runtime::DerivedKey;
use nscript_runtime::expiry::{is_expired, rumor_expiration};
use nscript_runtime::stream::check_channel_binding;
use nscript_runtime::wire::rumor_id;
use serde_json::Value;

use crate::group_key::{hex, xonly_pubkey};
use crate::nip44::conversation_key;
use crate::stream::{SealForm, open_stream_event};

/// Chat rumor kinds a reader delivers: a message and a threaded reply. Other
/// kinds (reactions, edits, deletes, presence) are not messages.
const KIND_MESSAGE: u64 = 9;
const KIND_THREADED_REPLY: u64 = 1111;

/// One message as a handler sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedMessage {
    /// The rumor id, recomputed from the decrypted bytes (an embedded `id` is
    /// never trusted).
    pub id: String,
    /// The seal's proven author.
    pub author: String,
    pub kind: u64,
    pub content: String,
    /// `created_at * 1000 + ms`, the basis every Concord comparison uses.
    pub time_ms: u64,
    pub tags: Vec<Vec<String>>,
}

/// Why an event did not reach the handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Dropped {
    /// Not addressed to this plane, not signed correctly, not decryptable, or
    /// an impersonation attempt.
    NotOpenable,
    /// The rumor's `channel`/`epoch` tags do not match the key that opened it.
    WrongBinding,
    /// Past its `expiration` (CORD-08).
    Expired,
    /// The author is on the Banlist.
    Banned,
    /// Already delivered.
    Duplicate,
    /// A kind that is not a message.
    NotAMessage,
    /// A malformed `ms` tag, or an unreadable rumor.
    Malformed,
}

/// Reads one Channel of one epoch.
pub struct ChannelReader {
    pubkey: [u8; 32],
    conv: [u8; 32],
    channel_id: String,
    epoch: u64,
    delivered: BTreeSet<String>,
}

impl ChannelReader {
    /// `key` is the Channel's plane key (from `derive_group_key`).
    ///
    /// Returns `None` if `key` is not a valid plane secret.
    #[must_use]
    pub fn new(key: &DerivedKey, channel_id: &str, epoch: u64) -> Option<Self> {
        let secret: [u8; 32] = key.as_bytes().try_into().ok()?;
        let pubkey = xonly_pubkey(&secret).ok()?;
        let conv = conversation_key(&secret, &pubkey).ok()?;
        Some(Self {
            pubkey,
            conv,
            channel_id: channel_id.to_owned(),
            epoch,
            delivered: BTreeSet::new(),
        })
    }

    /// The plane's public address: what a relay subscription filters `authors` on.
    #[must_use]
    pub fn address(&self) -> String {
        hex(&self.pubkey)
    }

    /// Judges one wrap. `banned` is the Banlist and `now` the current time in
    /// unix seconds.
    ///
    /// # Errors
    ///
    /// Returns the reason the event was dropped.
    pub fn ingest(
        &mut self,
        wrap_json: &str,
        now: u64,
        banned: &BTreeSet<String>,
    ) -> Result<ReceivedMessage, Dropped> {
        let opened = open_stream_event(&self.pubkey, &self.conv, SealForm::Encrypted, wrap_json)
            .map_err(|_| Dropped::NotOpenable)?;
        // A banned author vanishes entirely, before anything else is looked at.
        if banned.contains(&opened.author) {
            return Err(Dropped::Banned);
        }
        let rumor: Value =
            serde_json::from_str(&opened.rumor_json).map_err(|_| Dropped::Malformed)?;
        let kind = rumor
            .get("kind")
            .and_then(Value::as_u64)
            .ok_or(Dropped::Malformed)?;
        if kind != KIND_MESSAGE && kind != KIND_THREADED_REPLY {
            return Err(Dropped::NotAMessage);
        }
        let tags = tag_lists(&rumor).ok_or(Dropped::Malformed)?;
        // The binding stops a keyholder re-wrapping a message into another
        // Channel or replaying it across an epoch.
        check_channel_binding(&tags, &self.channel_id, self.epoch)
            .map_err(|_| Dropped::WrongBinding)?;
        let json_tags = rumor
            .get("tags")
            .and_then(Value::as_array)
            .ok_or(Dropped::Malformed)?;
        if is_expired(rumor_expiration(json_tags), now) {
            return Err(Dropped::Expired);
        }
        let created_at = rumor
            .get("created_at")
            .and_then(Value::as_u64)
            .ok_or(Dropped::Malformed)?;
        let time_ms = created_at * 1000 + millis(&tags)?;
        let id = rumor_id(&opened.rumor_json).ok_or(Dropped::Malformed)?;
        if !self.delivered.insert(id.clone()) {
            return Err(Dropped::Duplicate);
        }
        Ok(ReceivedMessage {
            id,
            author: opened.author,
            kind,
            content: rumor
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            time_ms,
            tags,
        })
    }

    /// Ingests many wraps and returns the deliverable messages in Concord's
    /// canonical order: by `(time_ms, id)`, so events in the same second still
    /// sort deterministically.
    pub fn ingest_all<'a>(
        &mut self,
        wraps: impl IntoIterator<Item = &'a str>,
        now: u64,
        banned: &BTreeSet<String>,
    ) -> Vec<ReceivedMessage> {
        let mut messages: Vec<ReceivedMessage> = wraps
            .into_iter()
            .filter_map(|wrap| self.ingest(wrap, now, banned).ok())
            .collect();
        messages.sort_by(|a, b| (a.time_ms, &a.id).cmp(&(b.time_ms, &b.id)));
        messages
    }
}

fn tag_lists(rumor: &Value) -> Option<Vec<Vec<String>>> {
    rumor
        .get("tags")?
        .as_array()?
        .iter()
        .map(|tag| {
            tag.as_array()?
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .collect()
}

/// The sub-second `ms` tag; absent is 0, and out of range is malformed rather
/// than interpreted (CORD-02 §5).
fn millis(tags: &[Vec<String>]) -> Result<u64, Dropped> {
    let Some(tag) = tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("ms"))
    else {
        return Ok(0);
    };
    let value = tag.get(1).ok_or(Dropped::Malformed)?;
    if value.len() > 1 && value.starts_with('0') {
        return Err(Dropped::Malformed);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|ms| *ms <= 999)
        .ok_or(Dropped::Malformed)
}
