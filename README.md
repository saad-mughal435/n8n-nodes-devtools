# n8n-nodes-devtools

[![CI](https://github.com/saad-mughal435/n8n-nodes-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/saad-mughal435/n8n-nodes-devtools/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@saadmughal435/n8n-nodes-devtools)](https://www.npmjs.com/package/@saadmughal435/n8n-nodes-devtools)
[![Node](https://img.shields.io/badge/Node-%E2%89%A520.15-339933)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178c6)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
[![n8n community node](https://img.shields.io/badge/n8n-community%20node-ff6d5a)](https://docs.n8n.io/integrations/community-nodes/)

A small, dependency-light **n8n community node** that bundles the developer &
crypto utilities you keep reaching for mid-workflow — **JWT sign/verify, hashing
(SHA-256/512 + HMAC), UUID / Nano ID, JSON↔CSV, base64, and regex extraction** —
so you don't have to drop into a Code node for them.

> **Why this exists.** I'm [Muhammad Saad](https://saadm.dev) — I build and run
> automation and backend systems. Every real workflow eventually needs to sign a
> token, hash a payload, mint an ID, reshape a CSV, or pull fields out of a blob
> of text. This node packages those primitives behind a clean Resource →
> Operation UI, with the actual logic kept pure and unit-tested. It's also a
> deliberate engineering sample: a programmatic `INodeType`, a thin execute()
> adapter over a framework-free core, and green CI.

---

## Operations

| Resource    | Operation                                          | What it does                                                                 |
| ----------- | -------------------------------------------------- | --------------------------------------------------------------------------- |
| **JWT**     | Sign                                               | HS256/384/512 or RS256; optional `expiresIn`                                 |
| **JWT**     | Verify                                             | Checks the signature **and** `exp` / `nbf`; pin the allowed algorithms       |
| **Hash**    | Hash                                               | SHA-256 / SHA-512, hex or base64 output                                      |
| **Hash**    | HMAC                                               | Keyed SHA-256 / SHA-512                                                      |
| **ID**      | UUID v4 · Nano ID                                  | `crypto.randomUUID()`; unbiased Nano ID from a 64-char alphabet             |
| **Convert** | JSON→CSV · CSV→JSON · Base64 encode/decode         | RFC 4180-correct CSV (quotes, escapes, embedded newlines)                    |
| **Extract** | Regex                                              | Returns `match`, `index`, and **named capture groups** as fields            |

`CSV to JSON` emits one output item per data row; everything else returns one
item per input item. Enable **Continue On Fail** to capture errors as
`{ "error": "…" }` instead of stopping the run.

## Install

**In n8n (self-hosted):** Settings → **Community Nodes** → **Install**, then enter
`@saadmughal435/n8n-nodes-devtools`.

**Or via npm:**

```bash
npm install @saadmughal435/n8n-nodes-devtools
```

**From source:**

```bash
git clone https://github.com/saad-mughal435/n8n-nodes-devtools.git
cd n8n-nodes-devtools
npm install && npm run build
npm link
# then, in your n8n custom-extensions dir (~/.n8n/custom):
npm link n8n-nodes-devtools
```

Restart n8n and the **DevTools** node appears in the node panel.

## Example workflows

Importable JSON lives in [`workflows/`](workflows/):

- [`jwt-sign-and-verify.json`](workflows/jwt-sign-and-verify.json) — sign a token, then verify it.
- [`hash-and-csv.json`](workflows/hash-and-csv.json) — turn rows into CSV, then SHA-256 the result.
- [`regex-extract.json`](workflows/regex-extract.json) — pull named fields out of an invoice string.

Import via n8n → **Workflows** → **Import from File**.

## Develop & test

The behaviour lives in a pure, n8n-free module
([`nodes/DevTools/operations.ts`](nodes/DevTools/operations.ts)) so it can be
tested directly; [`DevTools.node.ts`](nodes/DevTools/DevTools.node.ts) is a thin
adapter that maps node parameters onto it.

```bash
npm ci
npm run lint     # eslint + eslint-plugin-n8n-nodes-base
npm run build    # tsc -> dist/, then copies the icon + codex json
npm test         # jest, against operations.ts
```

CI runs all four on every push and PR (Node 22).

## Security notes

- **JWT verification** rejects tampered, **expired** (`exp`), and not-yet-valid
  (`nbf`) tokens via `jsonwebtoken`, and lets you **pin the accepted
  algorithms** to head off algorithm-confusion attacks.
- Secret / key / token fields use n8n's masked (`password`) input and are never
  written to node output.
- Hashing, HMAC, UUID and Nano ID use Node's built-in `crypto`; the Nano ID
  alphabet is exactly 64 characters so byte-masking introduces no modulo bias.

## Project layout

```
nodes/DevTools/
  DevTools.node.ts     # INodeType: UI schema + thin execute() adapter
  operations.ts        # pure logic — the unit-test surface (no n8n imports)
  DevTools.node.json   # codex metadata
  devtools.svg         # node icon
test/operations.test.ts
workflows/             # importable example workflows
.github/workflows/ci.yml
```

## License

MIT © [Muhammad Saad](https://saadm.dev)
