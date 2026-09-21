## What changes

<!-- A short description of the change and why it is needed. -->

## Which rule or requirement it serves

<!-- A Domain Rule (DR-*), a requirement (TR-*), an ADR, or a roadmap slice. -->

## How it was verified

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `cargo deny check`

<!-- For a change that needs a live Windows host to exercise fully, say so and how it was covered otherwise. -->

## Checklist

- [ ] The change is one concern, not several.
- [ ] A test that failed first now passes (`AGENTS.md` §6).
- [ ] No secret, password or token appears in a log, an audit entry, a reply, a config or this diff.
- [ ] User-visible behaviour is reflected in `README.md` and `docs/REQUIREMENTS.md`.
- [ ] Documents do not soft-wrap paragraphs (`AGENTS.md` §9).
- [ ] A decision rather than an implementation is recorded as an ADR, not only as code.
