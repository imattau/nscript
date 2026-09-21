//! Deterministic state folds with bounded storage and replay semantics.
//!
//! Events are ordered by `(created_at, id)` regardless of arrival order, so
//! every client folding the same event set reaches the same state.

use std::collections::BTreeMap;

/// Pure transition function applied to events in canonical order.
pub trait Reducer {
    type State: Clone;
    type Event: Clone;

    /// Returns the state after `event`. An `Err` rejects the event without
    /// affecting the fold.
    ///
    /// # Errors
    ///
    /// Returns a reducer-defined message when the event is invalid in `state`.
    fn apply(&self, state: &Self::State, event: &Self::Event) -> Result<Self::State, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FoldError {
    /// The bounded log is full; the event was not stored.
    CapacityExceeded { capacity: usize },
    /// An event with this id is already folded.
    Duplicate { id: String },
}

/// Outcome of inserting one event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FoldOutcome {
    Applied,
    /// The reducer rejected the event; it is retained as skipped so replay
    /// stays deterministic and it is not re-offered.
    Rejected(String),
}

pub struct Fold<R: Reducer> {
    reducer: R,
    initial: R::State,
    state: R::State,
    capacity: usize,
    log: BTreeMap<(u64, String), R::Event>,
    ids: std::collections::BTreeSet<String>,
}

impl<R: Reducer> Fold<R> {
    #[must_use]
    pub fn new(reducer: R, initial: R::State, capacity: usize) -> Self {
        Self {
            reducer,
            state: initial.clone(),
            initial,
            capacity,
            log: BTreeMap::new(),
            ids: std::collections::BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn state(&self) -> &R::State {
        &self.state
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.log.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// Inserts an event at its canonical position and replays the log.
    ///
    /// # Errors
    ///
    /// Returns [`FoldError`] for duplicate ids or when capacity is exhausted.
    pub fn insert(
        &mut self,
        created_at: u64,
        id: impl Into<String>,
        event: R::Event,
    ) -> Result<FoldOutcome, FoldError> {
        let id = id.into();
        if self.ids.contains(&id) {
            return Err(FoldError::Duplicate { id });
        }
        if self.log.len() >= self.capacity {
            return Err(FoldError::CapacityExceeded {
                capacity: self.capacity,
            });
        }
        self.ids.insert(id.clone());
        self.log.insert((created_at, id.clone()), event);
        let rejected = self.replay();
        Ok(rejected.get(&id).map_or(FoldOutcome::Applied, |reason| {
            FoldOutcome::Rejected(reason.clone())
        }))
    }

    /// Replays the whole log from the initial state, returning rejection
    /// reasons keyed by event id.
    pub fn replay(&mut self) -> BTreeMap<String, String> {
        let mut state = self.initial.clone();
        let mut rejected = BTreeMap::new();
        for ((_, id), event) in &self.log {
            match self.reducer.apply(&state, event) {
                Ok(next) => state = next,
                Err(reason) => {
                    rejected.insert(id.clone(), reason);
                }
            }
        }
        self.state = state;
        rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Concat;
    impl Reducer for Concat {
        type State = String;
        type Event = String;
        fn apply(&self, state: &String, event: &String) -> Result<String, String> {
            if event == "bad" {
                return Err("bad event".to_owned());
            }
            Ok(format!("{state}{event}"))
        }
    }

    #[test]
    fn arrival_order_does_not_change_state() {
        let mut a = Fold::new(Concat, String::new(), 8);
        let mut b = Fold::new(Concat, String::new(), 8);
        a.insert(1, "x", "A".into()).unwrap();
        a.insert(2, "y", "B".into()).unwrap();
        a.insert(2, "a", "C".into()).unwrap();
        b.insert(2, "a", "C".into()).unwrap();
        b.insert(2, "y", "B".into()).unwrap();
        b.insert(1, "x", "A".into()).unwrap();
        assert_eq!(a.state(), "ACB");
        assert_eq!(a.state(), b.state());
    }

    #[test]
    fn duplicates_and_capacity_are_rejected() {
        let mut fold = Fold::new(Concat, String::new(), 1);
        fold.insert(1, "x", "A".into()).unwrap();
        assert_eq!(
            fold.insert(2, "x", "B".into()),
            Err(FoldError::Duplicate { id: "x".into() })
        );
        assert_eq!(
            fold.insert(2, "y", "B".into()),
            Err(FoldError::CapacityExceeded { capacity: 1 })
        );
        assert_eq!(fold.state(), "A");
    }

    #[test]
    fn rejected_events_do_not_change_state() {
        let mut fold = Fold::new(Concat, String::new(), 4);
        fold.insert(1, "x", "A".into()).unwrap();
        assert!(matches!(
            fold.insert(2, "y", "bad".into()),
            Ok(FoldOutcome::Rejected(_))
        ));
        assert_eq!(fold.state(), "A");
        assert_eq!(fold.len(), 2);
    }
}
