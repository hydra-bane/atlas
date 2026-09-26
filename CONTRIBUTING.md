# Contributing

## Reporting a program

Use `npx hydra-bane report <program-id> --submit`, or the issue form. The bot handles the rest (see the README).

## Writing an entry

One pull request, one file: `entries/<id>.json`, where `id` looks like `kr.vendor.product` (country, vendor, product; it never changes). Copy an existing entry as a template. `node scripts/entry-validate.mjs` and `node --test scripts/*.test.mjs` must pass.

An entry states facts, each with a public source. It never states our opinion of the program.

- **Identification:** `names` (as shown in Apps & Features, plus common names), `vendor`, `tags.countries`, optionally `tags.kind` (a plain description such as `banking-security`).
- **`context`:** one neutral sentence, 10 to 400 characters: what the program is and why people have it. Example: *"Browser-to-PC security module that some Korean banking and government websites ask users to install."* Say who asks for it or who ships it; do not say whether it is good, bad, needed or unsafe.
- **Neutral words:** never write malware, virus, spyware, adware, trojan, scam, junk, bloatware, PUP, vulnerable, insecure, dangerous, 악성, 사기, 취약 or 위험 in `names`, `vendor`, `context`, `tags.kind` or `reinstall_note`. CI rejects them. Quoting an advisory or source title that uses them is fine.
- **`sources`:** at least one public page over `https` for the identification and the context sentence, with its `kind` (`vendor`, `government`, `security-research`, `news`, `regulator`, `package-manifest`), its date (publication date, or the date you read it when the page has none) and title. Good sources: the vendor's page, a bank's or agency's install guide, security research that describes the program. Forum posts and removal-tool sites are not sources.
- **Detection:** a code signer or an uninstall-registry match is required; file names alone are not accepted. Collect the signer and thumbprint on a real install with `Get-AuthenticodeSignature`. [winget-pkgs](https://github.com/microsoft/winget-pkgs) manifests are a good source for DisplayName, Publisher and ProductCode.
- **`detect.root_certs`:** subject substrings (4 to 200 characters) of root certificates the program installs, taken from a source or from `Get-ChildItem Cert:\LocalMachine\Root` on a PC with the program installed. List a certificate only when it belongs to this program, not to a vendor's whole product line. Hydra-bane checks each PC for them; the entry does not claim they are present everywhere.
- **Uninstall:** `signed-exe` needs the uninstaller's file name and a signer thumbprint it is signed with. `msi-product-code` needs the product codes. If neither is known, use `msi-product-code` with an empty list: Hydra-bane will then report the program but not run anything.
- **Do not copy** from closed-source removal lists. Data from other open lists needs a compatible license and the `source` field.
- New entries have `verified: false` and `verified_by: null`. An entry becomes verified after a VM run that detects, removes and reinstalls the program, with the log attached to the PR.

## Adding a new country

Start with identification, `context` and `sources` only, with `advisories: []`. That is a complete entry. You do not need to judge the program or research its security history.

## Advisories

Advisories come from official publishers: national CERTs (KISA, JVN, CERT-FR, BSI, NCSC), NVD, EUVD, CISA, or the vendor's own security notice. The weekly watch finds candidates in NVD, EUVD, the KISA RSS feeds and CISA KEV and opens a pull request listing them. To add one:

1. Open the advisory itself. Check that it is about this program on Windows (skip macOS-only or mobile-only advisories).
2. Copy its `title` exactly as published, its `date`, and its `url`.
3. Add `cve` when the advisory lists CVE ids, and `kev: true` when a CVE is in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
4. Add `affected` only from the versions the advisory states, in dotted form:
   - "1.1.4.3 이하" or "1.1.4.3 and earlier": `{"up_to": "1.1.4.3", "inclusive": true}`; "before 2.0": `{"up_to": "2.0", "inclusive": false}`.
   - "1.1.4.4 이상 1.1.4.6 이하" or "1.1.4.4 to 1.1.4.6": add the inclusive lower bound, `{"from": "1.1.4.4", "up_to": "1.1.4.6", "inclusive": true}`.
   - A list of single versions ("1.1.1.0, 1.1.2.6, 1.1.2.7"): `{"versions": ["1.1.1.0", "1.1.2.6", "1.1.2.7"]}`, with no other field.
   - If the advisory writes versions in another notation (Veraport's "v3863"), convert only when the vendor or a source shows the mapping, and cite that source in `sources`.
   - If the advisory states no versions, leave `affected` out rather than guess. Hydra-bane then shows the advisory without claiming it applies to the installed version.

Research articles are not advisories. They can be `sources` when they describe what the program is.
