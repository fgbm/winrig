//! Fixture for scripts/check-comments.sh. Every comment below must be flagged.

/// The user.
pub struct User;

/// Creates a tenant.
pub fn create_tenant() {}

/// Tenant record.
pub fn tenant_record() {}

// Fixed per review finding N2.
fn first() {}

// Fix for issue #17.
fn second() {}

// Slice W3 added this guard.
fn third() {}

// Now insert the row.
fn fourth() {}

// Then return the identifier.
fn fifth() {}

/// The function returns the number of rows.
fn count_rows() {}

/// The caller opens the file. The caller reads the value. The caller closes the file.
fn load_value() {}

// Комментарий на русском языке.
fn sixth() {}

fn seventh() {} // Комментарий на русском языке после кода.
