//! CORD-01/02 stream vocabulary: seal kinds, planes, key labels, binding.

/// Seal kind, declared by the wire kind so a reader never sniffs content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealKind {
    /// Kind 20013: the rumor is NIP-44 encrypted inside the wrap.
    Encrypted,
    /// Kind 20014: the seal's content is the rumor's JSON, byte-verbatim.
    Plaintext,
}

impl SealKind {
    #[must_use]
    pub fn wire_kind(self) -> u16 {
        match self {
            Self::Encrypted => 20013,
            Self::Plaintext => 20014,
        }
    }

    #[must_use]
    pub fn from_wire_kind(kind: u16) -> Option<Self> {
        match kind {
            20013 => Some(Self::Encrypted),
            20014 => Some(Self::Plaintext),
            _ => None,
        }
    }
}

/// A Community plane; each fixes its seal kind (CORD-02 §5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plane {
    Control,
    Chat,
    Guestbook,
    Rekey,
}

impl Plane {
    /// Only the Control Plane is plaintext-sealed, because compaction
    /// re-wraps its signed editions into a new epoch.
    #[must_use]
    pub fn seal_kind(self) -> SealKind {
        match self {
            Self::Control => SealKind::Plaintext,
            Self::Chat | Self::Guestbook | Self::Rekey => SealKind::Encrypted,
        }
    }
}

/// Domain labels for `group_key` (CORD-02 §4–5, CORD-03 §1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupKeyLabel {
    Channel,
    Control,
    ControlSigner,
    Guestbook,
}

impl GroupKeyLabel {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Channel => "concord/channel",
            Self::Control => "concord/control",
            Self::ControlSigner => "concord/control-signer",
            Self::Guestbook => "concord/guestbook",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingError {
    Missing(&'static str),
    Mismatch(&'static str),
}

/// CORD-01 Binding as CORD-03 §3 requires it: the rumor's tags must commit
/// `["channel", id]` and `["epoch", n]`, strict-equal to the coordinate whose
/// key opened the wrap. Absence fails.
///
/// # Errors
///
/// Returns [`BindingError`] when a tag is absent or differs.
pub fn check_channel_binding(
    tags: &[Vec<String>],
    channel_id: &str,
    epoch: u64,
) -> Result<(), BindingError> {
    let find = |name: &'static str| {
        tags.iter()
            .find(|tag| tag.first().map(String::as_str) == Some(name))
            .and_then(|tag| tag.get(1))
            .ok_or(BindingError::Missing(name))
    };
    if find("channel")? != channel_id {
        return Err(BindingError::Mismatch("channel"));
    }
    // Numbers are decimal strings with no leading zeros.
    if *find("epoch")? != epoch.to_string() {
        return Err(BindingError::Mismatch("epoch"));
    }
    Ok(())
}

/// Whether `value` is a 32-byte lowercase-hex string (CORD-01 Encoding).
#[must_use]
pub fn is_hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> Vec<Vec<String>> {
        pairs
            .iter()
            .map(|(a, b)| vec![(*a).to_owned(), (*b).to_owned()])
            .collect()
    }

    #[test]
    fn only_control_plane_is_plaintext_sealed() {
        assert_eq!(Plane::Control.seal_kind().wire_kind(), 20014);
        for plane in [Plane::Chat, Plane::Guestbook, Plane::Rekey] {
            assert_eq!(plane.seal_kind().wire_kind(), 20013);
        }
        assert_eq!(SealKind::from_wire_kind(13), None);
    }

    #[test]
    fn binding_requires_exact_channel_and_epoch() {
        let ok = tags(&[("channel", "c1"), ("epoch", "4")]);
        assert_eq!(check_channel_binding(&ok, "c1", 4), Ok(()));
        assert_eq!(
            check_channel_binding(&ok, "c2", 4),
            Err(BindingError::Mismatch("channel"))
        );
        assert_eq!(
            check_channel_binding(&ok, "c1", 5),
            Err(BindingError::Mismatch("epoch"))
        );
        let leading_zero = tags(&[("channel", "c1"), ("epoch", "04")]);
        assert_eq!(
            check_channel_binding(&leading_zero, "c1", 4),
            Err(BindingError::Mismatch("epoch"))
        );
        assert_eq!(
            check_channel_binding(&tags(&[("epoch", "4")]), "c1", 4),
            Err(BindingError::Missing("channel"))
        );
    }

    #[test]
    fn hex32_rejects_uppercase_and_wrong_length() {
        assert!(is_hex32(&"ab".repeat(32)));
        assert!(!is_hex32(&"AB".repeat(32)));
        assert!(!is_hex32("abcd"));
    }
}
