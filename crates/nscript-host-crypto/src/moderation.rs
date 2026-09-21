//! Real `concord04` moderation: authority-checked directives published as
//! Control Plane editions and Guestbook kicks (CORD-04 §4–§6).
//!
//! Two independent gates already apply before this host is reached: the
//! program's `OperationPolicy`, and here the CORD-04 rule that the acting
//! identity holds the permission bit and strictly outranks its target in the
//! owner-rooted Roster. The host also refuses to publish anything a reader
//! would drop: it cites the actor's own Grant and holds the keys it needs.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use nscript_runtime::authority::{
    AuthorityFold, banlist_locator, grant_locator, parse_banlist, parse_grant, perm,
};
use nscript_runtime::edition::{Edition, VSK_BANLIST, VSK_GRANT, Vac};
use nscript_runtime::wire::build_edition;
use nscript_runtime::{
    InvocationId, OperationHost, OperationValue, PublishReport, RelayHost, RuntimeError,
};

use crate::group_key::{group_key, hex, xonly_pubkey};
use crate::host::signed_event_from_wire;
use crate::stream::{SealForm, build_seal, build_wrap, rumor};

/// Everything a member holds about one Community epoch.
#[derive(Clone)]
pub struct CommunityKeys {
    pub community_id: [u8; 32],
    pub community_root: [u8; 32],
    pub epoch: u64,
    /// Held only by the owner and staff (CORD-02 §2); without it the host
    /// cannot write the Control Plane.
    pub control_root: Option<[u8; 32]>,
}

impl std::fmt::Debug for CommunityKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommunityKeys")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Publishes moderation directives as the acting identity.
pub struct ConcordModerationHost {
    author_secret: [u8; 32],
    actor: String,
    keys: CommunityKeys,
    authority: AuthorityFold,
    relays: Box<dyn RelayHost>,
    relayset: String,
    /// Fixed clock for tests; the system clock when `None`.
    pub fixed_time: Option<u64>,
}

impl std::fmt::Debug for ConcordModerationHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConcordModerationHost")
            .field("actor", &self.actor)
            .finish_non_exhaustive()
    }
}

fn denied(actor: &str, action: &str) -> RuntimeError {
    RuntimeError::AuthorityDenied {
        actor: actor.to_owned(),
        action: action.to_owned(),
    }
}

impl ConcordModerationHost {
    /// `authority` is the folded Control Plane the actor currently sees; the
    /// host extends it with what it publishes.
    ///
    /// # Panics
    ///
    /// Never in practice: the actor's public key is derived from a valid
    /// secret held by the caller.
    #[must_use]
    pub fn new(
        author_secret: [u8; 32],
        keys: CommunityKeys,
        authority: AuthorityFold,
        relays: Box<dyn RelayHost>,
        relayset: impl Into<String>,
    ) -> Self {
        let actor = hex(&xonly_pubkey(&author_secret).expect("valid author key"));
        Self {
            author_secret,
            actor,
            keys,
            authority,
            relays,
            relayset: relayset.into(),
            fixed_time: None,
        }
    }

    /// The folded state, including editions this host has published.
    #[must_use]
    pub fn authority(&self) -> &AuthorityFold {
        &self.authority
    }

    fn now(&self) -> u64 {
        self.fixed_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs())
        })
    }

    fn community_hex(&self) -> String {
        hex(&self.keys.community_id)
    }

    fn head(&self, vsk: u8, entity_id: &str) -> Option<Edition> {
        self.authority
            .heads(vsk)
            .into_iter()
            .find(|head| head.entity_id == entity_id)
    }

    /// The exact Grant the actor acts under, pinned by coordinate, version and
    /// hash. The owner needs none. Without a Grant, readers would drop the
    /// action, so the host refuses to publish it.
    fn citation(&self, action: &str) -> Result<Option<Vac>, RuntimeError> {
        if self.actor == self.authority_owner() {
            return Ok(None);
        }
        let eid = grant_locator(&self.community_hex(), &self.actor)
            .ok_or_else(|| denied(&self.actor, action))?;
        let grant = self
            .head(VSK_GRANT, &eid)
            .ok_or_else(|| denied(&self.actor, action))?;
        Ok(Some(Vac {
            grant_eid: eid,
            version: grant.version,
            hash: grant.hash().ok_or_else(|| denied(&self.actor, action))?,
        }))
    }

    fn authority_owner(&self) -> String {
        self.authority.roster().owner
    }

    fn deliver(&mut self, wire: &str) -> Result<PublishReport, RuntimeError> {
        let event = signed_event_from_wire(wire).ok_or_else(|| {
            RuntimeError::InvalidOperationArguments {
                operation: "publish".to_owned(),
            }
        })?;
        self.relays.publish(1, &event, &self.relayset)
    }

    /// Publishes an edition on the Control Plane: a plaintext seal signed by
    /// the actor, wrapped by the `control_root`-derived signer and encrypted
    /// under the `community_root`-derived read key (CORD-02 §5).
    fn publish_edition(
        &mut self,
        edition: &Edition,
        rumor_json: &str,
    ) -> Result<PublishReport, RuntimeError> {
        let control_root =
            self.keys
                .control_root
                .ok_or_else(|| RuntimeError::CapabilityDenied {
                    capability: "control_root".to_owned(),
                })?;
        let (cid, epoch) = (self.keys.community_id, self.keys.epoch);
        let signer = group_key("concord/control-signer", &control_root, &cid, Some(epoch));
        let read = group_key(
            "concord/control",
            &self.keys.community_root,
            &cid,
            Some(epoch),
        );
        let now = self.now();
        let invalid = |_| RuntimeError::InvalidOperationArguments {
            operation: "publish_edition".to_owned(),
        };
        let seal = build_seal(
            &read.conversation_key(),
            SealForm::Plaintext,
            &self.author_secret,
            rumor_json,
            now,
        )
        .map_err(invalid)?;
        let wire = build_wrap(
            &signer.secret_bytes(),
            &read.conversation_key(),
            &seal,
            &[],
            now,
        )
        .map_err(invalid)?;
        let report = self.deliver(&wire)?;
        if report.accepted() {
            self.authority.insert(edition.clone());
        }
        Ok(report)
    }

    /// Ban = the Banlist layer: silences the target instantly for every honest
    /// client. The cryptographic read-cut (a Refounding, CORD-06) is a
    /// separate, heavier step that this host does not perform.
    fn ban(&mut self, target: &str) -> Result<PublishReport, RuntimeError> {
        if !self
            .authority
            .roster()
            .can(&self.actor, perm::BAN, Some(target))
        {
            return Err(denied(&self.actor, "ban"));
        }
        let vac = self.citation("ban")?;
        let eid =
            banlist_locator(&self.community_hex()).ok_or_else(|| denied(&self.actor, "ban"))?;
        let previous = self.head(VSK_BANLIST, &eid);
        // A replace-entire list: keep everyone already banned and add the target.
        let mut list: BTreeSet<String> = previous
            .as_ref()
            .and_then(|head| parse_banlist(&head.content))
            .unwrap_or_default();
        list.insert(target.to_owned());
        let content = serde_json::to_string(&list.into_iter().collect::<Vec<_>>())
            .map_err(|_| denied(&self.actor, "ban"))?;
        let (edition, rumor_json) = build_edition(
            VSK_BANLIST,
            &eid,
            previous.as_ref(),
            &content,
            &self.actor,
            vac.as_ref(),
            self.now(),
        )
        .ok_or_else(|| denied(&self.actor, "ban"))?;
        self.publish_edition(&edition, &rumor_json)
    }

    /// Kick = Role Removal, then the Guestbook directive, in that order so the
    /// target's rank is gone before the departure lands. Role Removal is
    /// attempted only when the actor may perform it; otherwise the kick
    /// degrades to a weaker removal, never a broken one.
    fn kick(&mut self, target: &str) -> Result<PublishReport, RuntimeError> {
        let roster = self.authority.roster();
        if !roster.can(&self.actor, perm::KICK, Some(target)) {
            return Err(denied(&self.actor, "kick"));
        }
        let vac = self.citation("kick")?;
        let holds_roles = roster
            .grants
            .get(target)
            .is_some_and(|roles| !roles.is_empty());
        if holds_roles
            && self.keys.control_root.is_some()
            && roster.can(&self.actor, perm::MANAGE_ROLES, Some(target))
        {
            let eid = grant_locator(&self.community_hex(), target)
                .ok_or_else(|| denied(&self.actor, "kick"))?;
            let previous = self.head(VSK_GRANT, &eid);
            let content = format!(r#"{{"member":"{target}","role_ids":[]}}"#);
            if parse_grant(&content).is_some()
                && let Some((edition, rumor_json)) = build_edition(
                    VSK_GRANT,
                    &eid,
                    previous.as_ref(),
                    &content,
                    &self.actor,
                    vac.as_ref(),
                    self.now(),
                )
            {
                self.publish_edition(&edition, &rumor_json)?;
            }
        }
        // Guestbook kick (kind 3309): member-writable plane, encrypted seal.
        let now = self.now();
        let mut tags = vec![serde_json::json!(["p", target])];
        if let Some(vac) = &vac {
            tags.push(serde_json::json!([
                "vac",
                vac.grant_eid,
                vac.version.to_string(),
                vac.hash
            ]));
        }
        let kick = rumor(
            &self.author_secret,
            3309,
            &serde_json::Value::Array(tags),
            "",
            now,
        )
        .map_err(|_| denied(&self.actor, "kick"))?;
        let (cid, epoch) = (self.keys.community_id, self.keys.epoch);
        let book = group_key(
            "concord/guestbook",
            &self.keys.community_root,
            &cid,
            Some(epoch),
        );
        let seal = build_seal(
            &book.conversation_key(),
            SealForm::Encrypted,
            &self.author_secret,
            &kick.to_string(),
            now,
        )
        .map_err(|_| denied(&self.actor, "kick"))?;
        let wire = build_wrap(
            &book.secret_bytes(),
            &book.conversation_key(),
            &seal,
            &[],
            now,
        )
        .map_err(|_| denied(&self.actor, "kick"))?;
        self.deliver(&wire)
    }
}

impl OperationHost for ConcordModerationHost {
    fn call(
        &mut self,
        _invocation: InvocationId,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        let unavailable = || RuntimeError::OperationUnavailable {
            module: module.to_owned(),
            operation: operation.to_owned(),
        };
        if module != "concord04" {
            return Err(unavailable());
        }
        let [OperationValue::PubKey(target)] = arguments else {
            return Err(RuntimeError::InvalidOperationArguments {
                operation: operation.to_owned(),
            });
        };
        let roster = self.authority.roster();
        match operation {
            "can_kick" => Ok(OperationValue::Integer(i64::from(roster.can(
                &self.actor,
                perm::KICK,
                Some(target),
            )))),
            "can_ban" => Ok(OperationValue::Integer(i64::from(roster.can(
                &self.actor,
                perm::BAN,
                Some(target),
            )))),
            "kick_member" => self.kick(target).map(OperationValue::PublishReport),
            "ban_member" => self.ban(target).map(OperationValue::PublishReport),
            _ => Err(unavailable()),
        }
    }
}
