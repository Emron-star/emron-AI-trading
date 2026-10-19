# Deriv API contract notes — Phase 0

**Status: pending a live demo-account run.** Do not build the trading executor or proceed to Phase 1 until the required observations below are confirmed.

## Official documentation observations

- REST base: `https://api.derivws.com`.
- OAuth endpoints: `https://auth.deriv.com/oauth2/auth` and `https://auth.deriv.com/oauth2/token`.
- Options account list: `GET /trading/v1/options/accounts`.
- Account-scoped WebSocket URL: `POST /trading/v1/options/accounts/{accountId}/otp`, returning `data.url`.
- Current official Options API documentation says the OTP URL is single-use and valid for 120 seconds. The spike uses it once and does not print or save the URL.
- New API contract payloads use `underlying_symbol` for the underlying market.
- OAuth Authorization Code + PKCE is used; the access token is kept in process memory by the spike, never printed or persisted.

These details were checked against Deriv's public documentation on 2026-10-18. The live response from the account being tested takes precedence if it differs.

## Live questions to close

| Question | Required evidence | Status |
|---|---|---|
| Account fields | Full `GET /trading/v1/options/accounts` response; identify account type, ID field, currency and balance fields | Pending live run |
| WebSocket auth | OTP URL connects; first requests succeed without an `authorize` message; report optional `authorize` probe | Pending live run |
| Symbols | Active-symbol codes and five ticks each for `1HZ100V` and `R_100` | Pending live run |
| Pip precision | `pip_size` per symbol; verify digit extraction uses `Number(quote).toFixed(pip_size)` | Pending live run |
| Over contract type | `contracts_for` includes `DIGITOVER`; proposal response for `DIGITOVER` | Pending live run |
| Contract durations | Proposal responses for 1 tick plus an adaptive boundary probe for every digit type; infer only what is directly supported by results | Pending live run |
| Number types | Actual types returned for `ask_price`, `payout`, and `commission` | Pending live run |
| Buy path | One explicitly confirmed $1 demo trade, then `proposal_open_contract` until `is_sold=true` | Pending live run |
| Settlement | `contract_id`, `profit`, `sell_price`, entry/exit fields from Deriv | Pending live run |
| OTP lifetime | Official docs say 120 seconds, single-use; no destructive reuse probe is performed | Docs confirmed; not live-probed |
| Token expiry/refresh | Record `expires_in`; the app should re-login at expiry unless a documented refresh flow is confirmed | Pending live response / documentation review |

## Acceptance gate

Phase 0 passes only after the live run has confirmed all required fields and contract behavior, and one demo contract is settled and logged with its Deriv `contract_id`. See `docs/phase0-results.json` after running the spike. Do not regard an API proposal as a trade result; settlement requires Deriv's `is_sold` value.
