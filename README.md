# Hydra-bane Atlas

A community catalog, organized by country, of software people did not ask for and could not easily remove: bundled installers, adware, and leftovers from services that required an install. It is used by [Hydra-bane](https://github.com/hydra-bane/hydra-bane).

## How entries get here

1. A user asks their AI agent to get rid of an unwanted program. Hydra-bane offers to report it and shows exactly what would be posted: program name, publisher, code signer, file hash, and `%VAR%`-relative paths. It never includes a user name, PC name or real path.
2. If the user agrees, the report is posted here as an issue.
3. A bot validates the report and adds it to a **candidate** pull request, one per program. Repeat reports raise the count on the same PR.
4. Maintainers add first-hand evidence and a neutral category, then move the candidate to `entries/`. **Candidates are never shipped.**

Report from your own PC:

```powershell
npx hydra-bane programs
npx hydra-bane report <program-id>            # preview, sends nothing
npx hydra-bane report <program-id> --submit   # asks you, then posts
```

## Layout

- `candidates/`: bot-generated, unreviewed.
- `entries/`: reviewed entries that Hydra-bane uses.

## Disputes

If you publish software listed here and disagree, open an issue titled `[dispute] <entry id>`. The entry is taken out of default selection right away while the dispute is reviewed.

## License

Data: [CC BY-SA 4.0](LICENSE). The Hydra-bane CLI itself is Apache-2.0.
