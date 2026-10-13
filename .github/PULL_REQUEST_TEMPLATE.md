## What changes

<!-- A short description of the change and why it is necessary. -->

## Which rule or requirement it serves

<!-- A domain rule (DR-*), a requirement (TR-*), an ADR or a roadmap slice. -->

## How it is verified

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `cargo deny check`

<!-- For a change that only a live Windows host verifies fully, say so and how it is covered otherwise. -->

## Checklist

- [ ] The change is one topic, not several.
- [ ] The test that failed now passes (`AGENTS.md` §6).
- [ ] No secret, password or token appears in the log, the audit, the reply, the configuration or this diff.
- [ ] Behavior visible to a user is reflected in `README.md` and `docs/REQUIREMENTS.md`.
- [ ] Paragraphs in the documents are not wrapped by width (`AGENTS.md` §9).
- [ ] A decision, not an implementation, is recorded as an ADR, not only as code.
