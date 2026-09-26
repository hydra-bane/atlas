# Hydra-bane Atlas

A community catalog, organized by country, of programs people often find on their PC without having chosen them: security modules that banking and government websites ask for, preinstalled software, and bundled installers. [Hydra-bane](https://github.com/hydra-bane/hydra-bane) uses it to recognize these programs and to show the user facts about them. The user decides what to remove. Hydra-bane never removes anything without asking.

**The Atlas states facts, not verdicts.** An entry says what a program is, how to recognize and uninstall it, and what official advisories have said about it, each with a public source. It never calls a program good, bad, unwanted or unsafe.

## What is in it

| Entry | Country | Context (short) | Advisories (count, newest) |
|---|---|---|---|
| [AnySign4PC](entries/kr.hancomwith.anysign4pc.json) | KR | Signing with Korean public-key certificates in the browser | 7, 2026-09-01 |
| [TouchEn nxKey](entries/kr.raonsecure.touchen-nxkey.json) | KR | Keyboard protection asked for by banking and government sites | 4, 2025-07-07 |
| [Veraport](entries/kr.wizvera.veraport.json) | KR | Installation manager for the security programs sites ask for | 2, 2023-02-01 |
| [IPinside LWS Agent](entries/kr.interezen.ipinside-lws-agent.json) | KR | Sends PC and network details to banking sites for device identification | 1, 2023-02-01 |
| [AhnLab Safe Transaction](entries/kr.ahnlab.safe-transaction.json) | KR | Transaction protection asked for by banking and payment sites | 0 |
| [nProtect Online Security](entries/kr.inca.nprotect-online-security.json) | KR | Transaction protection asked for by banking and payment sites | 0 |
| [Superfish VisualDiscovery](entries/us.superfish.visualdiscovery.json) | US | Advertising program preinstalled on some Lenovo laptops (2014) | 3, 2015-02-24 |

No entry is `verified` yet: that needs a VM run of detect, remove and reinstall (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## What an entry contains

One JSON file per program, `entries/<id>.json`, in schema 2. The rules are those of `validateEntry` in the client's [`src/atlas/entry.ts`](https://github.com/hydra-bane/hydra-bane/blob/main/src/atlas/entry.ts); [scripts/entry-validate.mjs](scripts/entry-validate.mjs) is a port that CI runs on every change.

- **Identification:** `names`, `vendor`, `tags.countries`.
- **`context`:** one neutral sentence on what the program is and why people have it, for example *"Keyboard protection program that many Korean banking and government websites ask users to install to protect what is typed into web forms."* No verdict words (malware, vulnerable, 취약, 악성 and similar); CI rejects them in our own fields.
- **`sources`:** public pages behind the identification and the context sentence: the vendor's page, a bank's install guide, security research.
- **`detect`:** code signers (subject and thumbprints), uninstall-registry names, and `root_certs`: subject substrings of root certificates the program is known to install.
- **`uninstall`:** how to find the vendor's own uninstaller. There is no shell-command field.
- **`advisories`:** advisories from official publishers (KISA, NVD, EUVD, CISA and others), each with its URL, date and title **quoted as published**, CVE ids when it lists them, `kev: true` when a CVE is in CISA's Known Exploited Vulnerabilities catalog, and `affected`: the versions the advisory itself states, either a range (`up_to` and `inclusive`, with an optional inclusive lower bound `from`) or a list of single `versions`. When an advisory names no versions, `affected` is left out.
- **Bookkeeping:** `vendor_response`, `dispute`, `verified`, `added`, `last_reviewed`.

## What Hydra-bane does with an entry

- **It measures the rest on each user's PC.** Whether a listed root certificate is actually present, which local ports the program listens on, which services it starts, when it was installed: Hydra-bane checks these on the PC it runs on. The Atlas does not assert them for everyone.
- **An advisory applies only when it covers the installed version.** Hydra-bane reads the installed version and marks an advisory as applying only when that version is within `affected`. Versions outside it are shown as not covered. Advisories without a range are shown without a version match (unknown).
- **Nothing is selected for removal by default.** Many Korean entries are modules that banks and public websites still ask for. Removing one is safe for the PC, but the site may ask you to install it again.

## Where advisories come from

A weekly job ([.github/workflows/advisories.yml](.github/workflows/advisories.yml), [scripts/advisories.mjs](scripts/advisories.mjs)) asks NVD and EUVD for each entry's names and vendor, reads KISA's RSS feeds (security notices and vulnerability information), and checks CVEs against CISA KEV. Anything that names an entry and is not in it yet goes into one pull request, *advisories: new candidates*. The job never edits entries: a maintainer opens each advisory, reads the version range it states, and adds it.

## How a report becomes an entry

1. A user asks their AI agent to get rid of a program. Hydra-bane offers to report it and shows exactly what would be posted: program name, publisher, code signer, file hash, and `%VAR%`-relative paths. It never includes a user name, PC name or real path.
2. If the user agrees, the report is posted here as an issue.
3. A bot checks it and adds it to a **candidate** pull request, one per program. Repeat reports raise the count on the same PR. To limit spam, the bot pauses reports from GitHub accounts younger than 7 days and more than 5 reports per account in 24 hours (label `rate-limited`).
4. A maintainer turns the candidate into `entries/<id>.json`: identification, context and sources. **Candidates are never shipped.** Advisories are added from official feeds (above).
5. A release publishes `atlas-bundle.json` and its Ed25519 signature. Users get it only when they run `hydra-bane atlas update`.

Report from your own PC:

```powershell
npx hydra-bane programs
npx hydra-bane report <program-id>            # preview, sends nothing
npx hydra-bane report <program-id> --submit   # asks you, then posts
```

## Layout

- `entries/`: reviewed entries, one JSON file per program, named `<id>.json`.
- `candidates/`: bot output, unreviewed (user reports and advisory candidates).
- `scripts/`: entry validator, intake bot, advisory watch, bundle builder, and their tests.
- `bundle-seq.txt`: the `bundle_seq` of the last release. Clients refuse a bundle older than the one they have.

## Building a bundle (maintainers)

```powershell
node --test scripts/*.test.mjs
node scripts/entry-validate.mjs
$env:ATLAS_SIGNING_KEY = "<path to the offline private key>"
node scripts/bundle.mjs build --out dist --release   # writes dist/atlas-bundle.json(.sig), bumps bundle-seq.txt
node scripts/bundle.mjs verify dist/atlas-bundle.json
```

Commit `bundle-seq.txt` with the release, and upload both files from `dist/` to the GitHub release. The private key never enters this repository.

## Disputes

If you publish software listed here and a fact in its entry is wrong, see [DISPUTES.md](DISPUTES.md).

## License

Data: [CC BY-SA 4.0](LICENSE). The Hydra-bane CLI itself is Apache-2.0.
