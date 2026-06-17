# TokenTwin Checker

**Dual Token BAC / IDOR Tester for Burp Suite**

TokenTwin Checker is a Burp Suite extension that automates **Broken Access Control (BAC)** and **IDOR** testing. Give it tokens from two different accounts, send any request to it, and it replays that request with both tokens and compares the responses. If the responses are identical, User B was able to access User A's resource — that's BAC/IDOR by definition.

Built in Python for Jython, works on both Burp Suite Community and Professional.

---

## Table of contents

- [What it does](#what-it-does)
- [Installation](#installation)
- [Quick start](#quick-start)
- [UI reference](#ui-reference)
- [Smart Filter](#smart-filter)
- [Risk levels and patterns](#risk-levels-and-patterns)
- [Proof of Concept viewer](#proof-of-concept-viewer)
- [CSV export](#csv-export)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [License](#license)

---

## What it does

Say you found a request that returns data scoped to a specific user:

```
GET /api/v1/orders/3720719
Authorization: Bearer <token for user A>
```

The question is: if you replay the exact same request with **user B's** token, do you still get the same data back? If yes, that's BAC/IDOR.

TokenTwin Checker does this for hundreds of requests at once, shows results in a color-coded table, and filters out noise (static assets, irrelevant endpoints) so you only spend time on what's worth manually reviewing.

---

## Installation

### Prerequisite: Jython

Burp Suite needs Jython to run Python extensions.

1. Download: **https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar**
2. In Burp Suite: `Extender → Options → Python Environment`
3. Click `Select file` and choose `jython-standalone-2.7.4.jar`

### Installing the extension

1. Download `TokenTwin_Checker.py` from this repo
2. In Burp Suite: `Extender → Extensions → Add`
3. Set **Extension Type** to `Python`
4. Click `Select file` and choose `TokenTwin_Checker.py`
5. Click `Next`

If everything loaded correctly, a new **TokenTwin** tab appears in Burp's top menu bar, and the Output tab shows `TokenTwin Checker v3.0 loaded`.

If you see an error, check [Troubleshooting](#troubleshooting).

---

## Quick start

1. Get two tokens (Authorization header value or session cookie) from two different accounts — your own, and one belonging to a user you should *not* have access to.
2. Open the **TokenTwin** tab.
3. Set **Type**: `Header` or `Cookie`.
4. Set **Name**: the exact header or cookie name (default `Authorization` for Header, `session` for Cookie).
5. Paste Token 1 and Token 2.
6. Click **Save Tokens**.
7. Go to **Proxy → HTTP History** or a **Repeater** tab.
8. Right-click one or more requests that return user-specific data (multi-select with Shift/Ctrl works).
9. Click **"Send to TokenTwin Checker"**.
10. Switch back to the TokenTwin tab and check the results table.

---

## UI reference

### Config panel

| Field | Description |
|---|---|
| **Type** | Where the token lives: `Header` (e.g. Authorization) or `Cookie` (e.g. session) |
| **Name** | Exact header or cookie name to replace |
| **Token 1** | Full token value for user 1 (e.g. `Bearer eyJhbGci...`) |
| **Token 2** | Full token value for user 2 |
| **Ignore regex** | Pipe-separated regex patterns stripped from the response body before hashing — use this for fields that change on every request (nonce, timestamp, request-id) to avoid false negatives |
| **Smart Filter** | When enabled, skips static assets (js/css/png/...) entirely |

### Buttons

- **Save Tokens** — stores the tokens in memory. The context menu won't work until you do this.
- **Clear All** — wipes the results table, stored requests/responses, and the PoC viewer.
- **Export CSV** — saves the current table (respecting the active filter) to a CSV file.

### Progress bar

Shows percentage and a live count of tested / skipped / total requests while a batch is running.

### Results table

| Column | Description |
|---|---|
| **#** | Row number |
| **Method** | HTTP method |
| **URL** | Full request URL |
| **Risk** | Risk score based on URL pattern — `HIGH` / `MEDIUM` / `LOW` |
| **Pattern** | The exact reason for that risk score (e.g. "Numeric ID in path") |
| **St.T1 / Len T1** | Status code and body length for Token 1's response |
| **St.T2 / Len T2** | Status code and body length for Token 2's response |
| **Result** | Final comparison outcome |

Result column colors:
- 🔴 **Red** `SAME - Possible BAC/IDOR` — both responses match on status + body hash → worth investigating
- 🟢 **Green** `Different` — responses differ → access control is likely working
- 🟠 **Orange** `ERROR` — one of the two requests failed to send/receive

### Filter buttons (above the table)

- **All** — show everything
- **SAME only** — only rows flagged as SAME
- **HIGH risk only** — rows that are both Risk=HIGH and Result=SAME (the best starting point for manual review)

---

## Smart Filter

When you select hundreds of requests from Proxy History, most are static files (js/css/png) that have nothing to do with IDOR. Smart Filter skips them automatically so you get:

- Faster scans
- A clean results table
- Focus only on what could realistically be vulnerable

If you need to test *everything* with no exceptions (e.g. an API with no static assets), uncheck `Smart Filter`.

Skipped extensions: `js, css, png, jpg, jpeg, gif, svg, ico, woff, woff2, ttf, eot, map, pdf, zip`

---

## Risk levels and patterns

Every tested URL is matched against known IDOR/BAC indicators:

| Risk | Pattern | Example |
|---|---|---|
| HIGH | Numeric ID in path | `/orders/3720719` |
| HIGH | UUID in path | `/users/550e8400-e29b-41d4-...` |
| HIGH | IDOR param in query | `?user_id=123` |
| HIGH | Admin endpoint | `/admin/users` |
| MEDIUM | Numeric param value | `?ref=9988` |
| MEDIUM | Self-reference endpoint | `/me`, `/account`, `/profile` |
| LOW | Mutable method | POST/PUT/DELETE with no obvious ID |
| LOW | Generic endpoint | everything else |

This score is purely for **prioritizing manual review** — nothing is dropped because of a low score, it just tells you where to look first.

---

## Proof of Concept viewer

Click any row in the results table and the bottom panel renders the full **Request and Response for both tokens, side by side — exactly like Repeater**, using Burp's own native message editor (full syntax highlighting, Pretty/Raw/Hex tabs included).

```
┌─────────────── Token 1 ───────────────┬─────────────── Token 2 ───────────────┐
│  Request                              │  Request                              │
│  GET /api/v1/orders/3720719 HTTP/2    │  GET /api/v1/orders/3720719 HTTP/2    │
│  Authorization: Bearer <user A token> │  Authorization: Bearer <user B token> │
├────────────────────────────────────────┼────────────────────────────────────────┤
│  Response                             │  Response                             │
│  HTTP/2 200 OK                        │  HTTP/2 200 OK                        │
│  { ...JSON body... }                  │  { ...JSON body... }                  │
└────────────────────────────────────────┴────────────────────────────────────────┘
```

This is meant to be screenshotted (or copied) directly into your bug bounty report as proof.

Data is kept in memory and cleared on `Clear All` or when the extension is unloaded — nothing is written to disk.

---

## CSV export

Exports the current table (respecting whatever filter is active) to a `.csv` file — useful for attaching to a report or sharing with a team.

---

## Limitations

- Detection relies purely on **status code + body hash**. If the server includes dynamic fields (timestamps, request IDs, nonces) that make two *genuinely* identical responses look different (a **false negative**), add the relevant pattern to `Ignore regex`.
- A `SAME` result is not automatic proof of a vulnerability — for example, a public endpoint (`/products/123` open to everyone) is *expected* to return the same response for any user. Always validate against the actual business logic.
- Requests are processed **sequentially** to avoid hammering the target with concurrent traffic; large batches will take some time.
- Tokens live in memory only (RAM) and are never written to disk; they're lost when Burp closes.

---

## Troubleshooting

**Extension fails to load / Jython error**
→ Make sure `jython-standalone-2.7.4.jar` (not some other version) is selected under `Extender → Options → Python Environment`.

**"Send to TokenTwin Checker" doesn't show in the right-click menu**
→ Make sure at least one request is actually selected/highlighted, not just clicked once.

**Results table stays empty after sending**
→ Check whether Smart Filter is on and the request you sent is a static asset (js/png/...). If so, uncheck Smart Filter.

**Result always shows Different even when it should be SAME**
→ The response likely contains a dynamic field (timestamp, request-id, nonce). Add it to `Ignore regex`.

**Error in Output tab containing `Traceback`**
→ Copy the full error from `Extender → Extensions → TokenTwin Checker → Output` — usually caused by an unusual request/response format.

---

## FAQ

**Do I need two real accounts?**
Yes. You need two tokens from two different sessions/users — typically different privilege levels or different identities at the same level.

**Does this work on Burp Community Edition?**
Yes, it only uses the standard Burp Extender API, available in both Community and Professional.

**Why only Header and Cookie? What about body or query param tokens?**
The current version supports Header/Cookie because those are by far the most common places auth tokens live. Other injection points may be added in future versions.

---

## License & Credits

Built for use in authorized Bug Bounty engagements and penetration testing. You are solely responsible for how you use this tool — only test systems you have explicit permission to test.

Maintained by **rootdr**
- Telegram: [t.me/rootdr_research](https://t.me/rootdr_research)
- X (Twitter): [x.com/R00TDR](https://x.com/R00TDR)
