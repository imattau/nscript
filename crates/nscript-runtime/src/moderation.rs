//! Constrained moderation host for the `concord04` module.
//!
//! Two independent gates apply. The program's [`crate::OperationPolicy`] says
//! which operations a script may call at all (a bot granted only
//! `kick_member` cannot ban). This host then applies CORD-04 §5: the acting
//! identity must hold the permission bit and strictly outrank the target in the
//! owner-rooted Roster, regardless of what the script was granted.

use crate::authority::{Roster, perm};
use crate::{
    InvocationId, OperationHost, OperationValue, PublishReport, RelayOutcome, RuntimeError,
};

/// A directive the host produced on the acting identity's behalf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModerationAction {
    /// Cooperative Kick (Guestbook, kind 3309), after Role Removal.
    Kick { target: String },
    /// Banlist edition; the Refounding that enforces it follows separately.
    Ban { target: String },
}

pub struct ModerationHost {
    actor: String,
    roster: Roster,
    pub issued: Vec<ModerationAction>,
}

impl ModerationHost {
    /// `actor` is the real identity the bot signs as.
    #[must_use]
    pub fn new(actor: impl Into<String>, roster: Roster) -> Self {
        Self {
            actor: actor.into(),
            roster,
            issued: Vec::new(),
        }
    }

    /// Replaces the Roster after a re-fold, so revocations take effect at once.
    pub fn update_roster(&mut self, roster: Roster) {
        self.roster = roster;
    }

    fn target(operation: &str, arguments: &[OperationValue]) -> Result<String, RuntimeError> {
        match arguments {
            [OperationValue::PubKey(target)] if !target.is_empty() => Ok(target.clone()),
            _ => Err(RuntimeError::InvalidOperationArguments {
                operation: operation.to_owned(),
            }),
        }
    }

    fn require(&self, bit: u64, action: &str, target: &str) -> Result<(), RuntimeError> {
        if self.roster.can(&self.actor, bit, Some(target)) {
            Ok(())
        } else {
            Err(RuntimeError::AuthorityDenied {
                actor: self.actor.clone(),
                action: action.to_owned(),
            })
        }
    }

    fn accepted(detail: &str) -> OperationValue {
        OperationValue::PublishReport(PublishReport {
            outcomes: vec![RelayOutcome {
                relay: "fake://concord04".to_owned(),
                accepted: true,
                detail: detail.to_owned(),
            }],
        })
    }
}

impl OperationHost for ModerationHost {
    fn call(
        &mut self,
        _invocation: InvocationId,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        if module != "concord04" {
            return Err(RuntimeError::OperationUnavailable {
                module: module.to_owned(),
                operation: operation.to_owned(),
            });
        }
        let unavailable = || RuntimeError::OperationUnavailable {
            module: module.to_owned(),
            operation: operation.to_owned(),
        };
        let bit = match operation {
            "can_kick" | "kick_member" => perm::KICK,
            "can_ban" | "ban_member" => perm::BAN,
            _ => return Err(unavailable()),
        };
        let target = Self::target(operation, arguments)?;
        match operation {
            "can_kick" | "can_ban" => Ok(OperationValue::Integer(i64::from(self.roster.can(
                &self.actor,
                bit,
                Some(&target),
            )))),
            "kick_member" => {
                self.require(bit, "kick", &target)?;
                self.issued.push(ModerationAction::Kick { target });
                Ok(Self::accepted("kick directive issued"))
            }
            "ban_member" => {
                self.require(bit, "ban", &target)?;
                self.issued.push(ModerationAction::Ban { target });
                Ok(Self::accepted("banlist edition issued"))
            }
            _ => Err(unavailable()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Role;
    use crate::{
        FakeClock, FakeRelayHost, FakeSignerHost, OperationPolicy, RecordingAudit, Runtime,
    };

    const OWNER: &str = "01";
    const BOT: &str = "b0";
    const ADMIN: &str = "ad";
    const SPAMMER: &str = "5f";

    fn roster() -> Roster {
        let mut roster = Roster::new(OWNER);
        let role = |id: &str, position, permissions| Role {
            role_id: id.to_owned(),
            position,
            permissions,
            server_scope: true,
        };
        roster
            .roles
            .insert("mod".into(), role("mod", 5, perm::KICK));
        roster
            .roles
            .insert("admin".into(), role("admin", 1, perm::KICK | perm::BAN));
        roster.grants.insert(BOT.into(), vec!["mod".into()]);
        roster.grants.insert(ADMIN.into(), vec!["admin".into()]);
        roster
    }

    fn runtime() -> Runtime<FakeRelayHost, FakeSignerHost, FakeClock, RecordingAudit> {
        Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        )
    }

    fn call(
        runtime: &mut Runtime<FakeRelayHost, FakeSignerHost, FakeClock, RecordingAudit>,
        policy: &OperationPolicy,
        host: &mut ModerationHost,
        operation: &str,
        target: &str,
    ) -> Result<OperationValue, RuntimeError> {
        runtime.invoke_authorized_operation(
            policy,
            host,
            "concord04",
            operation,
            &[OperationValue::PubKey(target.to_owned())],
        )
    }

    #[test]
    fn kick_only_bot_can_kick_but_the_script_grant_blocks_ban() {
        let mut rt = runtime();
        let policy = OperationPolicy::default()
            .allow("concord04", "kick_member")
            .allow("concord04", "can_kick");
        let mut host = ModerationHost::new(BOT, roster());
        assert!(call(&mut rt, &policy, &mut host, "kick_member", SPAMMER).is_ok());
        assert_eq!(
            host.issued,
            vec![ModerationAction::Kick {
                target: SPAMMER.to_owned()
            }]
        );
        // Not granted to the script: denied before the host is reached.
        assert_eq!(
            call(&mut rt, &policy, &mut host, "ban_member", SPAMMER),
            Err(RuntimeError::CapabilityDenied {
                capability: "concord04.ban_member".to_owned()
            })
        );
        assert_eq!(host.issued.len(), 1);
    }

    #[test]
    fn roster_authority_binds_even_a_fully_granted_script() {
        let mut rt = runtime();
        let policy = OperationPolicy::default()
            .allow("concord04", "kick_member")
            .allow("concord04", "ban_member");
        let mut host = ModerationHost::new(BOT, roster());
        // The bot's rank has no BAN bit.
        assert!(matches!(
            call(&mut rt, &policy, &mut host, "ban_member", SPAMMER),
            Err(RuntimeError::AuthorityDenied { .. })
        ));
        // It has KICK but cannot act on a higher-ranked admin or the owner.
        for target in [ADMIN, OWNER] {
            assert!(matches!(
                call(&mut rt, &policy, &mut host, "kick_member", target),
                Err(RuntimeError::AuthorityDenied { .. })
            ));
        }
        assert!(host.issued.is_empty());
    }

    #[test]
    fn can_queries_reflect_rank_and_revocation_takes_effect_on_refold() {
        let mut rt = runtime();
        let policy = OperationPolicy::default().allow("concord04", "can_kick");
        let mut host = ModerationHost::new(BOT, roster());
        assert_eq!(
            call(&mut rt, &policy, &mut host, "can_kick", SPAMMER),
            Ok(OperationValue::Integer(1))
        );
        assert_eq!(
            call(&mut rt, &policy, &mut host, "can_kick", ADMIN),
            Ok(OperationValue::Integer(0))
        );
        // The bot is demoted: its Grant is stripped.
        let mut demoted = roster();
        demoted.grants.insert(BOT.into(), Vec::new());
        host.update_roster(demoted);
        assert_eq!(
            call(&mut rt, &policy, &mut host, "can_kick", SPAMMER),
            Ok(OperationValue::Integer(0))
        );
    }

    #[test]
    fn admin_can_ban_and_banned_actors_can_do_nothing() {
        let mut rt = runtime();
        let policy = OperationPolicy::default().allow("concord04", "ban_member");
        let mut host = ModerationHost::new(ADMIN, roster());
        assert!(call(&mut rt, &policy, &mut host, "ban_member", SPAMMER).is_ok());
        assert_eq!(
            host.issued,
            vec![ModerationAction::Ban {
                target: SPAMMER.to_owned()
            }]
        );
        let mut banned = roster();
        banned.banned.insert(ADMIN.to_owned());
        host.update_roster(banned);
        assert!(matches!(
            call(&mut rt, &policy, &mut host, "ban_member", SPAMMER),
            Err(RuntimeError::AuthorityDenied { .. })
        ));
    }
}
