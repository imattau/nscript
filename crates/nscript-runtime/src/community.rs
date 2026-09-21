//! CORD-02/03 community and channel state, folded deterministically.
//!
//! This models the structural plane only (epoch and channel set); authority
//! checks belong to the CORD-04 fold layered on top.

use std::collections::BTreeMap;

use crate::fold::Reducer;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommunityState {
    pub epoch: u64,
    /// Channel id to display name.
    pub channels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommunityEvent {
    ChannelCreated {
        id: String,
        name: String,
    },
    ChannelRenamed {
        id: String,
        name: String,
    },
    ChannelRemoved {
        id: String,
    },
    /// Rekey/refounding moves the community to a strictly later epoch.
    EpochAdvanced {
        epoch: u64,
    },
}

pub struct CommunityReducer;

impl Reducer for CommunityReducer {
    type State = CommunityState;
    type Event = CommunityEvent;

    fn apply(
        &self,
        state: &CommunityState,
        event: &CommunityEvent,
    ) -> Result<CommunityState, String> {
        let mut next = state.clone();
        match event {
            CommunityEvent::ChannelCreated { id, name } => {
                if id.is_empty() || name.is_empty() {
                    return Err("channel id and name must be non-empty".to_owned());
                }
                if next.channels.insert(id.clone(), name.clone()).is_some() {
                    return Err(format!("channel {id} already exists"));
                }
            }
            CommunityEvent::ChannelRenamed { id, name } => {
                let Some(slot) = next.channels.get_mut(id) else {
                    return Err(format!("channel {id} does not exist"));
                };
                if name.is_empty() {
                    return Err("channel name must be non-empty".to_owned());
                }
                name.clone_into(slot);
            }
            CommunityEvent::ChannelRemoved { id } => {
                if next.channels.remove(id).is_none() {
                    return Err(format!("channel {id} does not exist"));
                }
            }
            CommunityEvent::EpochAdvanced { epoch } => {
                if *epoch <= next.epoch {
                    return Err("epoch must strictly increase".to_owned());
                }
                next.epoch = *epoch;
            }
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fold::{Fold, FoldOutcome};

    fn created(id: &str, name: &str) -> CommunityEvent {
        CommunityEvent::ChannelCreated {
            id: id.to_owned(),
            name: name.to_owned(),
        }
    }

    #[test]
    fn channel_lifecycle_folds_in_canonical_order() {
        let mut fold = Fold::new(CommunityReducer, CommunityState::default(), 16);
        // Delivered out of order: rename (t=2) arrives before create (t=1).
        fold.insert(
            2,
            "e2",
            CommunityEvent::ChannelRenamed {
                id: "c1".into(),
                name: "general".into(),
            },
        )
        .unwrap();
        fold.insert(1, "e1", created("c1", "chat")).unwrap();
        assert_eq!(fold.state().channels["c1"], "general");
    }

    #[test]
    fn epoch_must_strictly_increase() {
        let mut fold = Fold::new(CommunityReducer, CommunityState::default(), 16);
        fold.insert(1, "e1", CommunityEvent::EpochAdvanced { epoch: 2 })
            .unwrap();
        let outcome = fold
            .insert(2, "e2", CommunityEvent::EpochAdvanced { epoch: 2 })
            .unwrap();
        assert!(matches!(outcome, FoldOutcome::Rejected(_)));
        assert_eq!(fold.state().epoch, 2);
    }

    #[test]
    fn duplicate_create_and_missing_remove_are_rejected() {
        let mut fold = Fold::new(CommunityReducer, CommunityState::default(), 16);
        fold.insert(1, "e1", created("c1", "a")).unwrap();
        assert!(matches!(
            fold.insert(2, "e2", created("c1", "b")).unwrap(),
            FoldOutcome::Rejected(_)
        ));
        assert!(matches!(
            fold.insert(3, "e3", CommunityEvent::ChannelRemoved { id: "zz".into() })
                .unwrap(),
            FoldOutcome::Rejected(_)
        ));
        assert_eq!(fold.state().channels.len(), 1);
    }
}
