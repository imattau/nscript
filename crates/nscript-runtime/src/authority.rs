//! CORD-04 owner-rooted authority: the Roster, Banlist and action judging.
//!
//! Authority is *rejection*: any `control_root` holder may publish an edition,
//! and every reader independently drops those whose sealed actor lacks the
//! rank. The fold starts at the owner (proven by the `community_id`) and
//! resolves outward, so it is iterated to a fixed point.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::edition::{
    Edition, EditionAuthority, EditionFold, FoldMode, VSK_BANLIST, VSK_CHANNEL_METADATA,
    VSK_COMMUNITY_METADATA, VSK_GRANT, VSK_ROLE, Vac,
};
use crate::stream::is_hex32;

/// Frozen permission bits (CORD-04 §3). Bit 7 is retired; 10 and 12 reserved.
pub mod perm {
    pub const MANAGE_ROLES: u64 = 1 << 0;
    pub const MANAGE_CHANNELS: u64 = 1 << 1;
    pub const MANAGE_METADATA: u64 = 1 << 2;
    pub const KICK: u64 = 1 << 3;
    pub const BAN: u64 = 1 << 4;
    pub const MANAGE_MESSAGES: u64 = 1 << 5;
    pub const CREATE_INVITE: u64 = 1 << 6;
    pub const VIEW_AUDIT_LOG: u64 = 1 << 8;
    pub const MENTION_EVERYONE: u64 = 1 << 9;
    pub const PIN_MESSAGES: u64 = 1 << 11;
    /// Bits whose actions land as Control editions: holders are staff.
    pub const STAFF: u64 =
        MANAGE_ROLES | MANAGE_CHANNELS | MANAGE_METADATA | BAN | CREATE_INVITE | PIN_MESSAGES;
}

pub const MAX_ROLES: usize = 100;
pub const MAX_ROLES_PER_MEMBER: usize = 64;
const MAX_ROUNDS: usize = 64;
/// Rank of a member holding no Role: below every real position.
const ROLELESS_RANK: u64 = u64::MAX;

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    block[..key.len()].copy_from_slice(key);
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let mut inner = Sha256::new();
    inner.update(pad(0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(pad(0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// CORD-02 A.1 HKDF-SHA256 with empty salt and a single 32-byte block.
fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(&[0_u8; 32], ikm);
    let mut expand = info.to_vec();
    expand.push(1);
    hmac_sha256(&prk, &expand)
}

fn hex_to_bytes32(value: &str) -> Option<[u8; 32]> {
    if !is_hex32(value) {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// `community_id = sha256("concord/community" || owner_xonly || owner_salt)`
/// (CORD-02 A.4). Returns `None` for malformed hex inputs.
#[must_use]
pub fn community_id(owner_xonly: &str, owner_salt: &str) -> Option<String> {
    let mut digest = Sha256::new();
    digest.update(b"concord/community");
    digest.update(hex_to_bytes32(owner_xonly)?);
    digest.update(hex_to_bytes32(owner_salt)?);
    Some(bytes_to_hex(&digest.finalize()))
}

/// A keyless coordinate: `hkdf(community_id, label, id)` with no epoch
/// (CORD-02 A.6).
fn locator(label: &str, community_id: &str, id: &[u8; 32]) -> Option<String> {
    let mut info = label.as_bytes().to_vec();
    info.push(0);
    info.extend_from_slice(id);
    Some(bytes_to_hex(&hkdf32(&hex_to_bytes32(community_id)?, &info)))
}

/// Coordinate of a member's Grant entity (`concord/grant`).
#[must_use]
pub fn grant_locator(community_id: &str, member: &str) -> Option<String> {
    locator("concord/grant", community_id, &hex_to_bytes32(member)?)
}

/// Coordinate of the community's Banlist entity (`concord/banlist`).
#[must_use]
pub fn banlist_locator(community_id: &str) -> Option<String> {
    locator("concord/banlist", community_id, &[0_u8; 32])
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Role {
    pub role_id: String,
    pub position: u32,
    pub permissions: u64,
    /// Only server-scoped roles confer community-wide permissions.
    pub server_scope: bool,
}

/// Parses a Role edition's content. `None` means the content must be ignored.
#[must_use]
pub fn parse_role(content: &str) -> Option<Role> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    let role_id = value.get("role_id")?.as_str()?;
    let name = value.get("name")?.as_str()?;
    if !is_hex32(role_id) || name.len() > crate::community::NAME_MAX_BYTES {
        return None;
    }
    let position = u32::try_from(value.get("position")?.as_u64()?).ok()?;
    // No Role may claim position 0: it belongs to the owner alone.
    if position == 0 {
        return None;
    }
    // A reader accepts a decimal string or a (legacy) number.
    let permissions = match value.get("permissions")? {
        serde_json::Value::String(text) => text.parse::<u64>().ok()?,
        serde_json::Value::Number(number) => number.as_u64()?,
        _ => return None,
    };
    let server_scope = value
        .get("scope")
        .and_then(|scope| scope.get("kind"))
        .and_then(serde_json::Value::as_str)
        == Some("server");
    Some(Role {
        role_id: role_id.to_owned(),
        position,
        permissions,
        server_scope,
    })
}

/// Parses a Grant edition's content into `(member, role_ids)`.
#[must_use]
pub fn parse_grant(content: &str) -> Option<(String, Vec<String>)> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    let member = value.get("member")?.as_str()?;
    if !is_hex32(member) {
        return None;
    }
    let ids = value.get("role_ids")?.as_array()?;
    if ids.len() > MAX_ROLES_PER_MEMBER {
        return None;
    }
    let ids = ids
        .iter()
        .map(|id| id.as_str().filter(|id| is_hex32(id)).map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    Some((member.to_owned(), ids))
}

/// Parses a Banlist edition's content.
#[must_use]
pub fn parse_banlist(content: &str) -> Option<BTreeSet<String>> {
    let list: Vec<String> = serde_json::from_str(content).ok()?;
    list.iter()
        .all(|npub| is_hex32(npub))
        .then(|| list.into_iter().collect())
}

/// The folded Roster and Banlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Roster {
    pub owner: String,
    pub roles: BTreeMap<String, Role>,
    pub grants: BTreeMap<String, Vec<String>>,
    pub banned: BTreeSet<String>,
}

impl Roster {
    #[must_use]
    pub fn new(owner: &str) -> Self {
        Self {
            owner: owner.to_owned(),
            roles: BTreeMap::new(),
            grants: BTreeMap::new(),
            banned: BTreeSet::new(),
        }
    }

    fn roles_of<'a>(&'a self, member: &str) -> impl Iterator<Item = &'a Role> {
        self.grants
            .get(member)
            .into_iter()
            .flatten()
            .filter_map(|id| self.roles.get(id))
            .filter(|role| role.server_scope)
    }

    /// Lower is higher: owner 0, then the lowest position among the member's
    /// Roles; a roleless member is effectively last.
    #[must_use]
    pub fn rank(&self, member: &str) -> u64 {
        if member == self.owner {
            return 0;
        }
        self.roles_of(member)
            .map(|role| u64::from(role.position))
            .min()
            .unwrap_or(ROLELESS_RANK)
    }

    /// Union of the member's Role bits. The owner is judged by rank, not bits,
    /// but is reported as holding every defined bit for convenience.
    #[must_use]
    pub fn permissions(&self, member: &str) -> u64 {
        if member == self.owner {
            return u64::MAX;
        }
        self.roles_of(member)
            .fold(0, |bits, role| bits | role.permissions)
    }

    /// Staff hold the `control_root`: the owner plus any holder of a
    /// Control-writing bit.
    #[must_use]
    pub fn is_staff(&self, member: &str) -> bool {
        member == self.owner || self.permissions(member) & perm::STAFF != 0
    }

    /// Whether `actor` may perform an action needing `bit` on `target`:
    /// the bit AND a strictly higher rank. Banned actors can do nothing.
    #[must_use]
    pub fn can(&self, actor: &str, bit: u64, target: Option<&str>) -> bool {
        if actor != self.owner && self.banned.contains(actor) {
            return false;
        }
        if actor != self.owner && self.permissions(actor) & bit == 0 {
            return false;
        }
        target.is_none_or(|target| self.rank(actor) < self.rank(target))
    }
}

/// Outcome of judging one edition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    Honored,
    Dropped,
    /// The cited Grant has not been synced (block-until-synced).
    Parked,
}

/// Judges editions against one fixed Roster snapshot.
struct Judge<'a> {
    community_id: &'a str,
    roster: &'a Roster,
    /// `(entity id, edition hash)` to edition, for `prev` and `vac` lookups.
    by_hash: &'a BTreeMap<(String, String), &'a Edition>,
}

impl Judge<'_> {
    fn predecessor(&self, edition: &Edition) -> Option<&Edition> {
        let prev = edition.prev.clone()?;
        self.by_hash
            .get(&(edition.entity_id.clone(), prev))
            .copied()
    }

    /// The citation must name the actor's own Grant coordinate and be synced
    /// with a matching hash; rank is then resolved against the *current*
    /// roster, so a stale citation grandfathers nothing.
    fn citation(&self, actor: &str, vac: Option<&Vac>) -> Result<(), Verdict> {
        let Some(vac) = vac else {
            return Err(Verdict::Dropped);
        };
        if grant_locator(self.community_id, actor).as_deref() != Some(vac.grant_eid.as_str()) {
            return Err(Verdict::Dropped);
        }
        match self.by_hash.get(&(vac.grant_eid.clone(), vac.hash.clone())) {
            Some(grant) if grant.version == vac.version => Ok(()),
            _ => Err(Verdict::Parked),
        }
    }

    fn judge(&self, edition: &Edition) -> Verdict {
        let roster = self.roster;
        let actor = edition.actor.as_str();
        let owner = actor == roster.owner;
        if !owner {
            if roster.banned.contains(actor) {
                return Verdict::Dropped;
            }
            if let Err(verdict) = self.citation(actor, edition.vac.as_ref()) {
                return verdict;
            }
        }
        let rank = roster.rank(actor);
        let has = |bit: u64| owner || roster.permissions(actor) & bit != 0;
        let allowed = match edition.vsk {
            VSK_COMMUNITY_METADATA => {
                has(perm::MANAGE_METADATA) && edition.entity_id == self.community_id
            }
            VSK_CHANNEL_METADATA => has(perm::MANAGE_CHANNELS),
            VSK_ROLE => self.role_allowed(edition, rank, has(perm::MANAGE_ROLES)),
            VSK_GRANT => self.grant_allowed(edition, rank, has(perm::MANAGE_ROLES)),
            VSK_BANLIST => self.banlist_allowed(edition, rank, has(perm::BAN)),
            _ => false,
        };
        if allowed {
            Verdict::Honored
        } else {
            Verdict::Dropped
        }
    }

    fn role_allowed(&self, edition: &Edition, rank: u64, has_bit: bool) -> bool {
        let Some(role) = parse_role(&edition.content) else {
            return false;
        };
        if !has_bit || role.role_id != edition.entity_id {
            return false;
        }
        // Neither the claimed position nor the role being edited may sit at
        // or above the signer.
        let prior_ok = self
            .predecessor(edition)
            .and_then(|prev| parse_role(&prev.content))
            .is_none_or(|prev| u64::from(prev.position) > rank);
        u64::from(role.position) > rank && prior_ok
    }

    fn grant_allowed(&self, edition: &Edition, rank: u64, has_bit: bool) -> bool {
        let Some((member, role_ids)) = parse_grant(&edition.content) else {
            return false;
        };
        if !has_bit
            || grant_locator(self.community_id, &member).as_deref() != Some(&edition.entity_id)
        {
            return false;
        }
        // The actor must strictly outrank every Role handed out...
        let hands_out_ok = role_ids.iter().all(|id| {
            self.roster
                .roles
                .get(id)
                .is_some_and(|role| u64::from(role.position) > rank)
        });
        // ...and the member's rank *before* this edition (a strip changes it).
        let before = self
            .predecessor(edition)
            .and_then(|prev| parse_grant(&prev.content))
            .map_or(ROLELESS_RANK, |(_, ids)| self.rank_of_roles(&ids));
        member != self.roster.owner && hands_out_ok && before > rank
    }

    fn rank_of_roles(&self, role_ids: &[String]) -> u64 {
        role_ids
            .iter()
            .filter_map(|id| self.roster.roles.get(id))
            .filter(|role| role.server_scope)
            .map(|role| u64::from(role.position))
            .min()
            .unwrap_or(ROLELESS_RANK)
    }

    fn banlist_allowed(&self, edition: &Edition, rank: u64, has_bit: bool) -> bool {
        let Some(list) = parse_banlist(&edition.content) else {
            return false;
        };
        if !has_bit || banlist_locator(self.community_id).as_deref() != Some(&edition.entity_id) {
            return false;
        }
        let previous = self
            .predecessor(edition)
            .and_then(|prev| parse_banlist(&prev.content))
            .unwrap_or_default();
        // Each newly banned npub must be strictly outranked; the owner never is.
        list.difference(&previous)
            .all(|target| target != &self.roster.owner && self.roster.rank(target) > rank)
    }
}

struct SnapshotAuthority<'a>(Judge<'a>);

impl EditionAuthority for SnapshotAuthority<'_> {
    fn is_authorized(&self, edition: &Edition) -> bool {
        self.0.judge(edition) == Verdict::Honored
    }
}

/// Holds every Control edition and folds them into a [`Roster`].
pub struct AuthorityFold {
    owner: String,
    community_id: String,
    mode: FoldMode,
    capacity: usize,
    editions: Vec<Edition>,
}

impl AuthorityFold {
    /// The owner is verified against the `community_id` commitment.
    ///
    /// Returns `None` if `community_id` is not the commitment of
    /// `(owner_xonly, owner_salt)`.
    #[must_use]
    pub fn new(
        owner_xonly: &str,
        owner_salt: &str,
        community_id: &str,
        mode: FoldMode,
        capacity: usize,
    ) -> Option<Self> {
        (self::community_id(owner_xonly, owner_salt)?.as_str() == community_id).then(|| Self {
            owner: owner_xonly.to_owned(),
            community_id: community_id.to_owned(),
            mode,
            capacity,
            editions: Vec::new(),
        })
    }

    /// Stores an edition (duplicates by rumor id are ignored). Returns `false`
    /// if the store is full.
    pub fn insert(&mut self, edition: Edition) -> bool {
        if self
            .editions
            .iter()
            .any(|held| held.rumor_id == edition.rumor_id && held.entity_id == edition.entity_id)
        {
            return true;
        }
        if self.editions.len() >= self.capacity {
            return false;
        }
        self.editions.push(edition);
        true
    }

    fn by_hash(&self) -> BTreeMap<(String, String), &Edition> {
        self.editions
            .iter()
            .filter_map(|e| Some(((e.entity_id.clone(), e.hash()?), e)))
            .collect()
    }

    fn fold_once(&self, roster: &Roster) -> Roster {
        let by_hash = self.by_hash();
        let authority = SnapshotAuthority(Judge {
            community_id: &self.community_id,
            roster,
            by_hash: &by_hash,
        });
        let mut fold = EditionFold::new(authority, self.mode, self.editions.len().max(1));
        for edition in &self.editions {
            let _ = fold.insert(edition.clone());
        }
        let mut next = Roster::new(&self.owner);
        let banlist_id = banlist_locator(&self.community_id);
        for id in fold.entity_ids() {
            let Some(head) = fold.head(id) else { continue };
            let content = &head.head.content;
            match head.head.vsk {
                VSK_ROLE => {
                    if let Some(role) = parse_role(content).filter(|r| r.role_id == id) {
                        next.roles.insert(role.role_id.clone(), role);
                    }
                }
                VSK_GRANT => {
                    if let Some((member, ids)) = parse_grant(content).filter(|(m, _)| {
                        grant_locator(&self.community_id, m).as_deref() == Some(id)
                    }) {
                        next.grants.insert(member, ids);
                    }
                }
                VSK_BANLIST if banlist_id.as_deref() == Some(id) => {
                    if let Some(list) = parse_banlist(content) {
                        next.banned = list;
                    }
                }
                _ => {}
            }
        }
        // The Community's 100-lowest-role-id cap.
        while next.roles.len() > MAX_ROLES {
            next.roles.pop_last();
        }
        next
    }

    /// Folds to the Roster fixed point, starting from the owner alone.
    #[must_use]
    pub fn roster(&self) -> Roster {
        let mut roster = Roster::new(&self.owner);
        for _ in 0..MAX_ROUNDS {
            let next = self.fold_once(&roster);
            if next == roster {
                break;
            }
            roster = next;
        }
        roster
    }

    /// Judges one edition against the settled Roster.
    #[must_use]
    pub fn verdict(&self, edition: &Edition) -> Verdict {
        let roster = self.roster();
        let by_hash = self.by_hash();
        Judge {
            community_id: &self.community_id,
            roster: &roster,
            by_hash: &by_hash,
        }
        .judge(edition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SALT: &str = "0202020202020202020202020202020202020202020202020202020202020202";
    const ALICE: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
    const BOB: &str = "bb00000000000000000000000000000000000000000000000000000000000002";
    const CAROL: &str = "cc00000000000000000000000000000000000000000000000000000000000003";
    const ADMIN_ROLE: &str = "1100000000000000000000000000000000000000000000000000000000000000";
    const MOD_ROLE: &str = "2200000000000000000000000000000000000000000000000000000000000000";

    struct World {
        cid: String,
        fold: AuthorityFold,
        next_id: u32,
    }

    impl World {
        fn new() -> Self {
            let cid = community_id(OWNER, SALT).unwrap();
            let fold = AuthorityFold::new(OWNER, SALT, &cid, FoldMode::Tracking, 256).unwrap();
            Self {
                cid,
                fold,
                next_id: 0,
            }
        }

        fn id(&mut self) -> String {
            self.next_id += 1;
            format!("{:08}", self.next_id)
        }

        fn edition(
            &mut self,
            vsk: u8,
            eid: &str,
            prev: Option<&Edition>,
            content: String,
            actor: &str,
            vac: Option<&Edition>,
        ) -> Edition {
            Edition {
                vsk,
                entity_id: eid.to_owned(),
                version: prev.map_or(1, |p| p.version + 1),
                prev: prev.map(|p| p.hash().unwrap()),
                content,
                actor: actor.to_owned(),
                rumor_id: self.id(),
                vac: vac.map(|g| Vac {
                    grant_eid: g.entity_id.clone(),
                    version: g.version,
                    hash: g.hash().unwrap(),
                }),
            }
        }

        fn role(
            &mut self,
            id: &str,
            pos: u32,
            bits: u64,
            actor: &str,
            vac: Option<&Edition>,
        ) -> Edition {
            let content = format!(
                r#"{{"role_id":"{id}","name":"r","position":{pos},"permissions":"{bits}","scope":{{"kind":"server"}},"color":0}}"#
            );
            self.edition(VSK_ROLE, id, None, content, actor, vac)
        }

        fn grant(
            &mut self,
            member: &str,
            roles: &[&str],
            prev: Option<&Edition>,
            actor: &str,
            vac: Option<&Edition>,
        ) -> Edition {
            let list = roles
                .iter()
                .map(|r| format!("\"{r}\""))
                .collect::<Vec<_>>()
                .join(",");
            let content = format!(r#"{{"member":"{member}","role_ids":[{list}]}}"#);
            let eid = grant_locator(&self.cid, member).unwrap();
            self.edition(VSK_GRANT, &eid, prev, content, actor, vac)
        }

        fn add(&mut self, edition: &Edition) {
            assert!(self.fold.insert(edition.clone()));
        }
    }

    #[test]
    fn hkdf_matches_rfc5869_case_3_and_ids_check_the_owner() {
        let okm = hkdf32(&[0x0b; 22], b"");
        assert_eq!(
            bytes_to_hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
        let cid = community_id(OWNER, SALT).unwrap();
        assert!(AuthorityFold::new(OWNER, SALT, &cid, FoldMode::Tracking, 8).is_some());
        assert!(AuthorityFold::new(ALICE, SALT, &cid, FoldMode::Tracking, 8).is_none());
    }

    #[test]
    fn owner_roots_a_delegation_chain_that_resolves_outward() {
        let mut w = World::new();
        let admin = w.role(ADMIN_ROLE, 1, perm::MANAGE_ROLES | perm::BAN, OWNER, None);
        let alice_grant = w.grant(ALICE, &[ADMIN_ROLE], None, OWNER, None);
        // Alice (admin, position 1) creates a Mod role at position 2.
        let modr = w.role(MOD_ROLE, 2, perm::KICK, ALICE, Some(&alice_grant));
        let bob_grant = w.grant(BOB, &[MOD_ROLE], None, ALICE, Some(&alice_grant));
        for e in [&admin, &alice_grant, &modr, &bob_grant] {
            w.add(e);
        }
        let roster = w.fold.roster();
        assert_eq!(roster.rank(ALICE), 1);
        assert_eq!(roster.rank(BOB), 2);
        assert!(roster.roles.contains_key(MOD_ROLE));
        assert!(roster.can(ALICE, perm::BAN, Some(BOB)));
        assert!(roster.can(BOB, perm::KICK, Some(CAROL)));
        assert!(!roster.can(BOB, perm::BAN, Some(CAROL)), "no BAN bit");
        assert!(!roster.can(BOB, perm::KICK, Some(ALICE)), "must outrank");
        assert!(
            !roster.can(ALICE, perm::BAN, Some(OWNER)),
            "owner unremovable"
        );
        assert!(roster.is_staff(ALICE) && !roster.is_staff(BOB));
    }

    #[test]
    fn nobody_promotes_themselves_or_claims_position_zero() {
        let mut w = World::new();
        let admin = w.role(ADMIN_ROLE, 1, perm::MANAGE_ROLES, OWNER, None);
        let alice_grant = w.grant(ALICE, &[ADMIN_ROLE], None, OWNER, None);
        for e in [&admin, &alice_grant] {
            w.add(e);
        }
        let peer = w.role(MOD_ROLE, 1, perm::KICK, ALICE, Some(&alice_grant));
        assert_eq!(
            w.fold.verdict(&peer),
            Verdict::Dropped,
            "at signer's position"
        );
        let zero = w.role(MOD_ROLE, 0, perm::KICK, OWNER, None);
        assert_eq!(
            w.fold.verdict(&zero),
            Verdict::Dropped,
            "position 0 is the owner's"
        );
        let outrank = w.role(MOD_ROLE, 2, perm::KICK, ALICE, Some(&alice_grant));
        assert_eq!(w.fold.verdict(&outrank), Verdict::Honored);
        let self_grant = w.grant(
            ALICE,
            &[ADMIN_ROLE],
            Some(&alice_grant),
            ALICE,
            Some(&alice_grant),
        );
        assert_eq!(
            w.fold.verdict(&self_grant),
            Verdict::Dropped,
            "equal cannot act on equal"
        );
    }

    #[test]
    fn citations_must_be_present_synced_and_matching() {
        let mut w = World::new();
        let admin = w.role(ADMIN_ROLE, 1, perm::MANAGE_ROLES, OWNER, None);
        let alice_grant = w.grant(ALICE, &[ADMIN_ROLE], None, OWNER, None);
        w.add(&admin);
        // Grant not yet synced: alice's action parks.
        let action = w.role(MOD_ROLE, 2, perm::KICK, ALICE, Some(&alice_grant));
        assert_eq!(w.fold.verdict(&action), Verdict::Parked);
        w.add(&alice_grant);
        assert_eq!(w.fold.verdict(&action), Verdict::Honored);
        // No citation at all.
        let bare = w.role(MOD_ROLE, 2, perm::KICK, ALICE, None);
        assert_eq!(w.fold.verdict(&bare), Verdict::Dropped);
        // Forked citation: right coordinate, wrong hash, parks.
        let mut forked = action.clone();
        forked.vac.as_mut().unwrap().hash = "00".repeat(32);
        assert_eq!(w.fold.verdict(&forked), Verdict::Parked);
        // Citing someone else's grant coordinate is dropped.
        let mut stolen = action;
        stolen.vac.as_mut().unwrap().grant_eid = grant_locator(&w.cid, BOB).unwrap();
        assert_eq!(w.fold.verdict(&stolen), Verdict::Dropped);
    }

    #[test]
    fn demotion_kills_pending_citations() {
        let mut w = World::new();
        let admin = w.role(ADMIN_ROLE, 1, perm::MANAGE_ROLES, OWNER, None);
        let alice_grant = w.grant(ALICE, &[ADMIN_ROLE], None, OWNER, None);
        let action = w.role(MOD_ROLE, 2, perm::KICK, ALICE, Some(&alice_grant));
        for e in [&admin, &alice_grant] {
            w.add(e);
        }
        assert_eq!(w.fold.verdict(&action), Verdict::Honored);
        // Owner strips alice's roles; the old citation grandfathers nothing.
        let strip = w.grant(ALICE, &[], Some(&alice_grant), OWNER, None);
        w.add(&strip);
        assert_eq!(w.fold.roster().rank(ALICE), ROLELESS_RANK);
        assert_eq!(w.fold.verdict(&action), Verdict::Dropped);
    }

    #[test]
    fn banlist_needs_ban_bit_and_strict_outrank_and_silences_the_banned() {
        let mut w = World::new();
        let admin = w.role(ADMIN_ROLE, 1, perm::BAN | perm::MANAGE_ROLES, OWNER, None);
        let modr = w.role(MOD_ROLE, 2, perm::KICK, OWNER, None);
        let alice_grant = w.grant(ALICE, &[ADMIN_ROLE], None, OWNER, None);
        let bob_grant = w.grant(BOB, &[MOD_ROLE], None, OWNER, None);
        for e in [&admin, &modr, &alice_grant, &bob_grant] {
            w.add(e);
        }
        let banlist_eid = banlist_locator(&w.cid).unwrap();
        let ban = |w: &mut World, who: &str, list: &[&str], vac: &Edition| {
            let items = list
                .iter()
                .map(|m| format!("\"{m}\""))
                .collect::<Vec<_>>()
                .join(",");
            w.edition(
                VSK_BANLIST,
                &banlist_eid,
                None,
                format!("[{items}]"),
                who,
                Some(vac),
            )
        };
        let by_bob = ban(&mut w, BOB, &[CAROL], &bob_grant);
        assert_eq!(w.fold.verdict(&by_bob), Verdict::Dropped, "mod lacks BAN");
        let ban_owner = ban(&mut w, ALICE, &[OWNER], &alice_grant);
        assert_eq!(w.fold.verdict(&ban_owner), Verdict::Dropped);
        let ban_peer_admin = {
            let peer = w.grant(CAROL, &[ADMIN_ROLE], None, OWNER, None);
            w.add(&peer);
            ban(&mut w, ALICE, &[CAROL], &alice_grant)
        };
        assert_eq!(
            w.fold.verdict(&ban_peer_admin),
            Verdict::Dropped,
            "peers are equal"
        );
        let ban_bob = ban(&mut w, ALICE, &[BOB], &alice_grant);
        assert_eq!(w.fold.verdict(&ban_bob), Verdict::Honored);
        w.add(&ban_bob);
        let roster = w.fold.roster();
        assert!(roster.banned.contains(BOB));
        // Every later edition from bob is dropped, even a valid-looking one.
        let later = w.role("33".repeat(32).as_str(), 3, 0, BOB, Some(&bob_grant));
        assert_eq!(w.fold.verdict(&later), Verdict::Dropped);
        assert!(!roster.can(BOB, perm::KICK, Some(CAROL)));
    }
}
