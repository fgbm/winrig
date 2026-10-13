# ADR-0016 — Documentation language and style

- Status: accepted
- Date: 2026-10-13
- Related: AGENTS.md §9, ADR-0009

## Context

AGENTS.md section 9 made Russian the language of the repository documents. The product goes public on GitHub, so the code and the documentation have a wider audience. The operator decided to change the language of the repository text to English.

A second problem: the text had no formal style. Sentences and terms drifted between documents.

## Decision

1. The language of the repository text is English. The text obeys ASD-STE100 Simplified Technical English. The guide is in `docs/style/ste-en.md`.
2. Russian stays only in `README.ru.md` and in the Russian part of the docs site `docs/site/src/content/docs/ru/`. The Russian guide is in `docs/style/ru-technical.md`.
3. Code comments and doc comments are not STE. They use plain short technical English. The rules are in AGENTS.md.
4. Vale checks each Markdown file in CI at the error level. The English text uses the style `WinrigEN`. The Russian text uses the style `WinrigRU`.
5. The glossary in `docs/style/ste-en.md` is the single source of terms. Each concept has one term.
6. This decision replaces the language rule of AGENTS.md section 9.

## Consequences

- All existing documents receive a translation to English in later commits.
- Each documentation commit is in English.
- The documentation site is bilingual and lives on GitHub Pages.
- A future script checks the comments in the source code.
- The glossary is the point of change for each new term.
