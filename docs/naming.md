# Naming: finding a searchable name

Notes for a possible rename, 2026-10-28. Nothing here is decided.

## The problem

"Cosign" is hard to find. A search for it returns Sigstore's
[cosign](https://github.com/sigstore/cosign) (container signing, in Homebrew and most
supply-chain guides) and dictionary or loan pages for "cosigner". "Cosignr" doesn't
escape either: search engines read it as a typo for "cosigner", and it still sits next to
Sigstore's tool.

## Options

**Keep the name, always qualified.** Say "Cosign for Nostr" or `nostr-cosign` wherever
someone might search: the repository name, the app listing, the NIP's title, package
names. People looking for this search "nostr signer", so adding "nostr" does most of the
work. The cheapest change: nothing published breaks.

**A coined word.** Best for search, since results are empty until this fills them.

| Name | Why |
|---|---|
| Fourpoint | The threshold: 4 points to sign, a device worth 3, a server 1. |
| Tetrad | Four parts making one. |
| Keyweave | A key woven from pieces, none of which is the key. |
| Keyfold | A key folded into pieces. |
| Marble Signer | Rides on Marble, which already has a distinct name. |

**Avoid** names with a dropped letter (Cosignr, Signr), which get autocorrected, and
common words already crowded in this space (Quorum, Keystone, Vault, Guardian).

## Before choosing

Check, for the name picked:

- npm, crates.io and Maven (`cc.aaro…` group names stay as they are either way)
- the GitHub organisation and repository name
- the domain (cosign.aaro.cc already works, so this matters less)
- a Play Store and Zapstore search
- a plain web search, logged out, for the bare word

## What a rename touches

The protocol's wire names (`cosign_req`, the `cosign-member` QRST profile, the
`cc.aaro.cosign` packages) don't need to change with the product name, and changing them
would break every installed device and server. A rename can stay at the surface: the
README, the app and store listings, the server's page, the NIP title.
