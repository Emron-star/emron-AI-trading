# Deriv Auto-Trader Console — Phase 0

This is the **first gated phase** of the site build based on the supplied 16-page specification. The brief says not to move to authentication/account UI or trading UI until the Phase 0 API spike passes, so this package verifies the contract and connection assumptions first.

The script:

1. Runs OAuth 2.0 Authorization Code + PKCE and keeps the token in memory only.
2. Reads and prints the Options account response locally, then selects a Demo account only.
3. Gets a fresh one-use WebSocket OTP URL without printing or saving that URL.
4. Connects without sending an initial `authorize` request.
5. Tests `active_symbols`, `ticks_history`, five live ticks for `1HZ100V` and `R_100`, and `contracts_for`.
6. Requests 1-, 10-, and 11-tick proposals for all six digit contract types. These proposal probes do not buy contracts.
7. Offers exactly one $1 `DIGITEVEN` demo trade after the operator types `BUY DEMO CONTRACT`, then waits for Deriv settlement. If a buy acknowledgement is missing, it checks portfolio and **never retries the buy**.
8. Tests an optional `authorize` message after the initial flow and writes a redacted summary to `docs/phase0-results.json`.

No trade outcome, balance or history is fabricated. A proposal is not a trade. The script will not buy a real-money contract, and it stops if no Demo account can be positively identified.

## Requirements

- Node.js 22 or newer (the spike uses the built-in WebSocket client; no npm dependency install is required).
- A Deriv OAuth 2.0 app registered in the Deriv developer dashboard.
- The exact client ID and redirect URI registered for that app.
- Access to your Deriv **Demo** account.

## Configure

1. Copy `.env.example` to `.env`.
2. Fill in `DERIV_CLIENT_ID` and `DERIV_REDIRECT_URI`.
3. Ensure the redirect URI exactly matches the URI registered with Deriv. For development, `http://localhost` can be used if you registered it.
4. Verify syntax:

```bash
npm run check
```

5. Run the spike:

```bash
npm run spike
```

6. A browser authorization URL will be printed. Sign in through Deriv. When redirected, copy the **full callback URL** from the browser address bar and paste it into the terminal. If the localhost page does not render, the URL may still be visible in the address bar.
7. Review the account list carefully. The script refuses to proceed if no account has `account_type: "demo"`.
8. The $1 demo purchase only occurs after typing exactly `BUY DEMO CONTRACT`. Press Enter to skip it.
9. Share `docs/phase0-results.json` and any relevant terminal errors for the next implementation phase. The JSON summary excludes tokens, OTP URLs and account IDs. Do not share any access token or authorization code.

## Important notes

- The script prints every account field to your local terminal because the specification explicitly asks for the account response. Review the terminal output before sharing it; it can contain your account identifier.
- The saved report is created with restrictive local file permissions, and it is ignored by Git.
- The OTP is redacted because it is a one-use credential. It is not written to the report.
- The live API may differ from documentation. Record returned response fields in `docs/deriv-contract.md` and trust the live response when there is a discrepancy.
- Phase 0 may stop with `NOT YET PASSED` if a check fails or the demo purchase is skipped. That is intentional: do not proceed to the UI phases until the API path is verified.

## Official references

- [Deriv API overview](https://developers.deriv.com/docs/intro/api-overview/)
- [Deriv OAuth 2.0 + PKCE](https://developers.deriv.com/docs/intro/oauth/)
- [Options account setup and OTP](https://developers.deriv.com/docs/options/)
- [Options WebSocket OTP details](https://developers.deriv.com/docs/options/websocket/)
- [Trading workflows](https://developers.deriv.com/docs/workflows/)
