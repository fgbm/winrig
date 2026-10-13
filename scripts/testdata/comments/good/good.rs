//! Fixture for scripts/check-comments.sh. No comment below may be flagged.

// DR-4: the password never reaches the log or the audit.
// See ADR-0009 for the profile token and the rotation.
// AC-PRF-48 requires the refusal to name the variable.
// TR-3 keeps the TLS check on by default.

/// The lock is held for the whole call, so a second process refuses to start.
pub fn lock_profile() {}

/// A recursive delete refuses the volume roots and every reparse point (DR-6).
pub fn remove_tree() {}
