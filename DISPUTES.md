# Disputes

The Atlas states facts with sources: what a program is, how to recognize and uninstall it, and what official advisories said about it, quoted with the versions they cover. If you publish software listed here, or you have evidence that a fact in an entry is wrong, you can dispute it.

## How

Open an issue titled `[dispute] <entry id>` (for example `[dispute] kr.wizvera.veraport`). Include:

- which statement in the entry you disagree with (the context sentence, a detection rule, a root certificate, an advisory or its version range),
- your evidence (a vendor page, a corrected advisory, a fixed version, a changed installer),
- a public link to your response, if you want it shown with the entry.

Publishers do not need an account with us beyond GitHub, and do not need to prove anything before the dispute is opened.

## What happens

1. **At once:** a maintainer sets `dispute.status` to `open` and releases a new bundle.
2. **Within 14 days:** maintainers decide, and write the reason in the issue.
   - `upheld`: the entry is corrected, or removed if it cannot be supported by sources.
   - `rejected`: the entry stays as it was.
3. **Always:** a link to the publisher's response is added to `vendor_response` and stays there for as long as the entry exists, whatever the decision.

## What we will change

- **Context and identification:** corrected when a source shows they are wrong or out of date.
- **Advisories:** we quote the publisher; we do not rewrite what it said. If the publisher corrected or withdrew an advisory, we follow the publisher. If a version range was copied wrongly, we fix it to match the advisory. A newer version outside an advisory's range already shows as not covered, so a fixed release needs no dispute; tell us if the advisory's own range is wrong and the publisher has updated it.
- **Root certificates and detection:** corrected when they match something that is not this program.

We do not remove true, sourced statements because they are unwelcome.

## Takedown requests

For legal notices, open an issue titled `[legal] <entry id>`, or use the contact on the maintainer's GitHub profile if the matter cannot be public.
