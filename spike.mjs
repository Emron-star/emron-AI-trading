import { createHash, randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
const WebSocket = globalThis.WebSocket;
if (!WebSocket) throw new Error('Node.js 22 or newer is required for the built-in WebSocket client.');

const API_BASE = 'https://api.derivws.com';
const AUTH_BASE = 'https://auth.deriv.com/oauth2';
const REPORT_PATH = resolve('docs/phase0-results.json');
const rl = createInterface({ input, output });
const envText = await readFile(resolve('.env'), 'utf8').catch(() => '');
for (const line of envText.split(/\r?\n/)) {
  const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
  if (match && !match[1].startsWith('#') && process.env[match[1]] === undefined) {
    process.env[match[1]] = match[2].replace(/^(['\"])(.*)\1$/, '$2');
  }
}

const results = {
  startedAt: new Date().toISOString(),
  apiBase: API_BASE,
  oauth: {},
  accounts: {},
  otp: {},
  websocket: {},
  symbols: {},
  ticks: {},
  contractsFor: {},
  proposals: [],
  durationProbes: [],
  authorizationMessageProbe: {},
  demoTrade: {},
  notes: [],
};

function section(title) {
  console.log(`\n${'='.repeat(76)}\n${title}\n${'='.repeat(76)}`);
}

function redact(value, secrets = []) {
  if (Array.isArray(value)) return value.map((item) => redact(item, secrets));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (/access_token|refresh_token|authorization_code|code_verifier/i.test(key)) {
        out[key] = '[REDACTED]';
      } else if (key === 'url' && typeof item === 'string' && item.startsWith('wss://')) {
        out[key] = item.replace(/([?&]otp=)[^&]+/i, '$1[REDACTED]');
      } else {
        out[key] = redact(item, secrets);
      }
    }
    return out;
  }
  if (typeof value === 'string') {
    let text = value;
    for (const secret of secrets) {
      if (secret && text.includes(secret)) text = text.split(secret).join('[REDACTED]');
    }
    return text;
  }
  return value;
}

function printJson(title, value, secrets = []) {
  console.log(`\n${title}\n${JSON.stringify(redact(value, secrets), null, 2)}`);
}

function printableError(error) {
  return error instanceof Error ? error.message : String(error);
}

async function ask(question) {
  return (await rl.question(question)).trim();
}

function safeAccountShape(account) {
  // Account IDs are intentionally only printed to the local terminal for selection;
  // they are omitted from the saved summary report.
  const type = String(account?.account_type ?? account?.type ?? '').toLowerCase();
  return {
    accountType: type || 'unknown',
    hasAccountId: Boolean(account?.account_id ?? account?.id ?? account?.accountId),
    currency: account?.currency ?? null,
    status: account?.status ?? null,
    balanceFieldPresent: account?.balance !== undefined,
    isDemo: type === 'demo',
    isReal: type === 'real',
  };
}

async function exchangeOAuthCode() {
  const clientId = process.env.DERIV_CLIENT_ID?.trim();
  const redirectUri = process.env.DERIV_REDIRECT_URI?.trim();
  if (!clientId || !redirectUri || clientId.startsWith('replace_')) {
    throw new Error('Set DERIV_CLIENT_ID and DERIV_REDIRECT_URI first. See .env.example and README.md.');
  }

  // OAuth PKCE verifier and state are kept in memory only; neither is logged or saved.
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(24).toString('base64url');
  const authorizeUrl = new URL(`${AUTH_BASE}/auth`);
  authorizeUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'trade',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();

  section('1. OAuth 2.0 + PKCE');
  console.log('Open this URL in your browser and sign in to Deriv:');
  console.log(authorizeUrl.toString());
  console.log('\nAfter Deriv redirects you, copy the FULL URL from the address bar.');
  console.log('If the localhost page does not load, the callback URL may still be visible in the address bar.');
  const callbackInput = await ask('\nPaste the full callback URL here: ');
  let callback;
  try {
    callback = new URL(callbackInput);
  } catch {
    throw new Error('That is not a valid URL. Paste the full callback URL, including code and state.');
  }
  const oauthError = callback.searchParams.get('error');
  if (oauthError) {
    throw new Error(`OAuth authorization failed: ${oauthError}${callback.searchParams.get('error_description') ? ` — ${callback.searchParams.get('error_description')}` : ''}`);
  }
  const returnedState = callback.searchParams.get('state');
  const code = callback.searchParams.get('code');
  if (!returnedState || returnedState !== state) {
    throw new Error('OAuth state did not match. Aborting to protect against a forged callback. Restart the spike and try again.');
  }
  if (!code) throw new Error('No authorization code was found in the callback URL.');

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    code_verifier: verifier,
    redirect_uri: redirectUri,
  });
  const response = await fetch(`${AUTH_BASE}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  const tokenData = await response.json().catch(() => ({}));
  if (!response.ok || !tokenData.access_token) {
    printJson('OAuth token endpoint response (secrets redacted)', tokenData, [code]);
    throw new Error(`OAuth token exchange failed (HTTP ${response.status}). See the returned Deriv error above.`);
  }
  results.oauth = {
    tokenExchangeHttpStatus: response.status,
    expiresInSeconds: Number(tokenData.expires_in) || null,
    tokenType: tokenData.token_type ?? null,
    accessTokenReceived: true,
    tokenPrintedOrSaved: false,
  };
  console.log(`OAuth exchange succeeded. expires_in: ${tokenData.expires_in ?? 'not returned'} seconds.`);
  console.log('Access token: received, but not printed or saved.');
  return { token: tokenData.access_token, clientId, redirectUri };
}

async function restRequest(path, token, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  return { status: response.status, ok: response.ok, data };
}

function getAccounts(payload) {
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.data?.accounts)) return payload.data.accounts;
  if (payload?.data && typeof payload.data === 'object') return [payload.data];
  if (Array.isArray(payload?.accounts)) return payload.accounts;
  return [];
}

class RpcSocket {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 100;
    this.listeners = new Set();
    this.closed = false;
    socket.addEventListener('message', (event) => {
      let message;
      try { message = JSON.parse(typeof event.data === 'string' ? event.data : String(event.data)); } catch { return; }
      for (const listener of [...this.listeners]) {
        try { listener(message); } catch (error) { console.error('Message listener error:', printableError(error)); }
      }
    });
    socket.addEventListener('close', () => { this.closed = true; });
  }

  onMessage(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  request(payload, timeoutMs = 12000) {
    if (this.closed || this.socket.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error('WebSocket is not open.'));
    }
    const reqId = ++this.nextId;
    const request = { ...payload, req_id: reqId };
    return new Promise((resolveRequest, rejectRequest) => {
      const timer = setTimeout(() => {
        off();
        rejectRequest(new Error(`Timed out waiting for req_id ${reqId} (${Object.keys(payload)[0]}).`));
      }, timeoutMs);
      const off = this.onMessage((message) => {
        if (message?.req_id !== reqId) return;
        clearTimeout(timer);
        off();
        resolveRequest(message);
      });
      try {
        this.socket.send(JSON.stringify(request));
      } catch (error) {
        clearTimeout(timer);
        off();
        rejectRequest(error);
      }
    });
  }

  send(payload) {
    if (this.closed || this.socket.readyState !== WebSocket.OPEN) throw new Error('WebSocket is not open.');
    this.socket.send(JSON.stringify(payload));
  }

  async close() {
    if (this.socket.readyState === WebSocket.CLOSED) return;
    await new Promise((resolveClose) => {
      const finish = () => { clearTimeout(timeout); resolveClose(); };
      const timeout = setTimeout(finish, 1500);
      this.socket.addEventListener('close', finish, { once: true });
      try { this.socket.close(); } catch { finish(); }
    });
  }
}

async function openRpcSocket(url) {
  const socket = new WebSocket(url);
  await new Promise((resolveOpen, rejectOpen) => {
    const timer = setTimeout(() => rejectOpen(new Error('Timed out opening Deriv WebSocket.')), 15000);
    socket.addEventListener('open', () => { clearTimeout(timer); resolveOpen(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); rejectOpen(new Error('WebSocket connection failed. Check the OTP URL, network and Deriv status.')); }, { once: true });
  });
  return new RpcSocket(socket);
}

function formatQuote(quote, pipSize) {
  const n = Number(quote);
  if (!Number.isFinite(n) || !Number.isFinite(pipSize)) return String(quote);
  return n.toFixed(pipSize);
}

function finalDigit(quote, pipSize) {
  return formatQuote(quote, pipSize).slice(-1);
}

async function captureTicks(rpc, symbol) {
  section(`Live ticks: ${symbol}`);
  let pipSize = null;
  let historyResponse;
  try {
    historyResponse = await rpc.request({
      ticks_history: symbol,
      end: 'latest',
      count: 1,
      style: 'ticks',
      subscribe: 0,
    });
    printJson(`${symbol} ticks_history response`, historyResponse);
    if (historyResponse.error) {
      results.ticks[symbol] = { historyOk: false, error: historyResponse.error.message ?? historyResponse.error.code };
      return;
    }
    pipSize = Number(historyResponse.pip_size);
    if (!Number.isInteger(pipSize) || pipSize < 0 || pipSize > 10) pipSize = null;
  } catch (error) {
    results.ticks[symbol] = { historyOk: false, error: printableError(error) };
    console.log(`ticks_history did not complete: ${printableError(error)}`);
    return;
  }

  const ticks = [];
  let resolveFive;
  let rejectFive;
  const fiveTicks = new Promise((resolvePromise, rejectPromise) => {
    resolveFive = resolvePromise;
    rejectFive = rejectPromise;
  });
  const timeout = setTimeout(() => rejectFive(new Error(`Timed out waiting for five ${symbol} ticks.`)), 90000);
  const off = rpc.onMessage((message) => {
    if (message?.msg_type !== 'tick' || message?.tick?.symbol !== symbol) return;
    if (ticks.length >= 5) return;
    ticks.push(message);
    const quote = message.tick.quote;
    const display = pipSize === null ? String(quote) : formatQuote(quote, pipSize);
    console.log(`${symbol} tick ${ticks.length}/5: quote=${display}, finalDigit=${pipSize === null ? 'unknown (pip_size unavailable)' : finalDigit(quote, pipSize)}, epoch=${message.tick.epoch ?? 'n/a'}`);
    if (ticks.length === 5) resolveFive();
  });

  let ack;
  try {
    ack = await rpc.request({ ticks: symbol, subscribe: 1 }, 15000);
    printJson(`${symbol} ticks subscription acknowledgement`, ack);
    if (ack.error) throw new Error(`${ack.error.code ?? 'Deriv error'}: ${ack.error.message ?? 'tick subscription rejected'}`);
    if (ticks.length < 5) await fiveTicks;
  } catch (error) {
    console.log(`${symbol} stream test failed: ${printableError(error)}`);
  } finally {
    clearTimeout(timeout);
    off();
    const subscriptionId = ack?.subscription?.id;
    if (subscriptionId) {
      try {
        const forget = await rpc.request({ forget: subscriptionId }, 8000);
        printJson(`${symbol} forget acknowledgement`, forget);
      } catch (error) {
        console.log(`Could not confirm stream release for ${symbol}: ${printableError(error)}`);
      }
    }
  }

  results.ticks[symbol] = {
    historyOk: !historyResponse?.error,
    pipSize,
    capturedTicks: ticks.length,
    subscriptionAckReceived: Boolean(ack && !ack.error),
    digitsUseFixedDecimalFormatting: pipSize !== null,
    passed: ticks.length === 5 && pipSize !== null,
  };
}

function specFor(contractType) {
  const spec = {
    DIGITMATCH: { contract_type: 'DIGITMATCH', barrier: '7' },
    DIGITDIFF: { contract_type: 'DIGITDIFF', barrier: '7' },
    DIGITEVEN: { contract_type: 'DIGITEVEN' },
    DIGITODD: { contract_type: 'DIGITODD' },
    DIGITOVER: { contract_type: 'DIGITOVER', barrier: '3' },
    DIGITUNDER: { contract_type: 'DIGITUNDER', barrier: '3' },
  }[contractType];
  return { ...spec };
}

async function requestProposal(rpc, { symbol, currency, amount = 1, contractType, duration = 1 }) {
  const spec = specFor(contractType);
  const payload = {
    proposal: 1,
    amount,
    basis: 'stake',
    ...spec,
    currency,
    duration,
    duration_unit: 't',
    underlying_symbol: symbol,
    subscribe: 0,
  };
  const response = await rpc.request(payload, 15000);
  printJson(`${contractType} proposal (${duration} tick${duration === 1 ? '' : 's'})`, response);
  const proposal = response?.proposal;
  return {
    contractType,
    duration,
    ok: !response.error && Boolean(proposal?.id),
    error: response.error ? { code: response.error.code ?? null, message: response.error.message ?? null } : null,
    proposalIdPresent: Boolean(proposal?.id),
    askPriceType: proposal?.ask_price === undefined ? 'missing' : typeof proposal.ask_price,
    payoutType: proposal?.payout === undefined ? 'missing' : typeof proposal.payout,
    commissionType: proposal?.commission === undefined ? 'missing' : typeof proposal.commission,
    proposalId: proposal?.id ?? null,
    askPrice: proposal?.ask_price === undefined ? null : Number(proposal.ask_price),
    payout: proposal?.payout === undefined ? null : Number(proposal.payout),
    rawResponse: redact(response),
  };
}

async function main() {
  section('Deriv Auto-Trader Console — Phase 0 API Spike');
  console.log('This test uses a real Deriv virtual/demo account for the one purchase.');
  console.log('It does not place any real-money trades, store tokens, or invent results.');

  const { token } = await exchangeOAuthCode();

  section('2. GET options accounts');
  const accountResponse = await restRequest('/trading/v1/options/accounts', token);
  results.accounts.httpStatus = accountResponse.status;
  results.accounts.ok = accountResponse.ok;
  if (!accountResponse.ok) {
    printJson('Options accounts endpoint response', accountResponse.data);
    throw new Error(`GET /trading/v1/options/accounts failed with HTTP ${accountResponse.status}.`);
  }
  const accounts = getAccounts(accountResponse.data);
  results.accounts.count = accounts.length;
  results.accounts.summary = accounts.map(safeAccountShape);
  printJson('Full account response fields (account IDs are local console output only)', accountResponse.data, [token]);
  if (!accounts.length) throw new Error('The accounts endpoint returned no recognizable account records. Check docs/phase0-results.json.');

  const demoAccounts = accounts.filter((account) => String(account?.account_type ?? account?.type ?? '').toLowerCase() === 'demo');
  if (!demoAccounts.length) {
    throw new Error('No account with account_type="demo" was found. Refusing to proceed to proposals or a purchase.');
  }
  console.log('\nAvailable demo accounts:');
  demoAccounts.forEach((account, index) => {
    const id = account.account_id ?? account.id ?? account.accountId ?? '(account id missing)';
    const currency = account.currency ?? '(currency missing)';
    const status = account.status ?? '(status missing)';
    const balance = account.balance ?? '(balance field missing)';
    console.log(`  [${index}] ${id} | ${currency} | status=${status} | balance=${balance}`);
  });
  let selectedIndex = 0;
  if (demoAccounts.length > 1) {
    const entered = await ask('Choose a demo account index: ');
    selectedIndex = Number(entered);
    if (!Number.isInteger(selectedIndex) || selectedIndex < 0 || selectedIndex >= demoAccounts.length) {
      throw new Error('Invalid demo account index.');
    }
  }
  const account = demoAccounts[selectedIndex];
  const accountId = account.account_id ?? account.id ?? account.accountId;
  const currency = account.currency === undefined || account.currency === null ? '' : String(account.currency);
  if (!accountId) throw new Error('Selected demo account has no recognizable account ID.');
  if (!currency) {
    results.notes.push('Selected account did not expose currency; trade was blocked instead of assuming one.');
    throw new Error('Selected demo account did not return a currency field. Refusing to quote or buy until the live account schema is understood.');
  }
  results.accounts.selected = {
    ...safeAccountShape(account),
    accountIdFieldName: account.account_id ? 'account_id' : account.id ? 'id' : 'accountId',
    accountIdOmittedFromReport: true,
    demoOnly: true,
  };

  section('3. Request a fresh one-time WebSocket URL (OTP)');
  const otpResult = await restRequest(`/trading/v1/options/accounts/${encodeURIComponent(accountId)}/otp`, token, { method: 'POST', body: '{}' });
  results.otp.httpStatus = otpResult.status;
  results.otp.ok = otpResult.ok;
  printJson('OTP response shape (the one-time URL is redacted)', otpResult.data, [token]);
  const wsUrl = otpResult?.data?.data?.url ?? otpResult?.data?.url;
  if (!otpResult.ok || typeof wsUrl !== 'string' || !wsUrl.startsWith('wss://')) {
    throw new Error(`OTP endpoint failed or returned no data.url (HTTP ${otpResult.status}).`);
  }
  results.otp.readyToUseWebSocketUrlReturned = true;
  results.otp.urlPrintedOrSaved = false;
  results.otp.urlTtlDocumentedSeconds = 120;
  results.otp.singleUseDocumented = true;

  section('4. Connect to the returned Options WebSocket; do not send authorize yet');
  const rpc = await openRpcSocket(wsUrl);
  results.websocket.connected = true;
  results.websocket.initialAuthorizeSent = false;
  console.log('WebSocket opened. Initial checks will run without an authorize message.');

  try {
    section('5. active_symbols check');
    const symbolsResponse = await rpc.request({ active_symbols: 'brief', product_type: 'basic' });
    printJson('active_symbols response', symbolsResponse, [token]);
    if (symbolsResponse.error) {
      results.symbols.error = { code: symbolsResponse.error.code ?? null, message: symbolsResponse.error.message ?? null };
    } else {
      const symbols = symbolsResponse.active_symbols ?? symbolsResponse.activeSymbols ?? [];
      const codes = new Set(symbols.map((item) => item?.symbol).filter(Boolean));
      results.symbols = {
        responseOk: true,
        count: symbols.length,
        found1HZ100V: codes.has('1HZ100V'),
        foundR100: codes.has('R_100'),
        requestedCodes: ['1HZ100V', 'R_100'],
      };
    }

    await captureTicks(rpc, '1HZ100V');
    await captureTicks(rpc, 'R_100');

    section('6. contracts_for — check digit contracts and DIGITOVER');
    const contractsResponse = await rpc.request({ contracts_for: 'R_100' });
    printJson('contracts_for response', contractsResponse, [token]);
    if (contractsResponse.error) {
      results.contractsFor = { ok: false, error: contractsResponse.error.message ?? contractsResponse.error.code };
    } else {
      const available = contractsResponse?.contracts_for?.available ?? [];
      const contractTypes = available.map((item) => item?.contract_type).filter(Boolean);
      results.contractsFor = {
        ok: true,
        symbol: 'R_100',
        itemCount: available.length,
        contractTypes,
        digitOverAvailable: contractTypes.includes('DIGITOVER'),
        digitUnderAvailable: contractTypes.includes('DIGITUNDER'),
      };
    }

    section('7. Proposal contract type and duration probes (no purchases in this section)');
    const types = ['DIGITMATCH', 'DIGITDIFF', 'DIGITEVEN', 'DIGITODD', 'DIGITOVER', 'DIGITUNDER'];
    const proposalResults = new Map();
    for (const contractType of types) {
      try {
        const result = await requestProposal(rpc, { symbol: 'R_100', currency, contractType, duration: 1 });
        results.proposals.push({ ...result, rawResponse: undefined });
        proposalResults.set(contractType, result);
      } catch (error) {
        const record = { contractType, duration: 1, ok: false, error: printableError(error) };
        results.proposals.push(record);
        console.log(`${contractType} proposal did not complete: ${printableError(error)}`);
      }
    }

    // Probe 10 and 11 ticks non-committing. These help establish the practical duration boundary
    // without risking any additional contracts. Rejections are API observations, not assumptions.
    async function probeDuration(contractType, duration) {
      const existing = results.durationProbes.find((item) => item.contractType === contractType && item.duration === duration);
      if (existing) return existing;
      try {
        const result = await requestProposal(rpc, { symbol: 'R_100', currency, contractType, duration });
        const row = {
          contractType,
          duration,
          ok: result.ok,
          error: result.error,
          askPriceType: result.askPriceType,
          payoutType: result.payoutType,
        };
        results.durationProbes.push(row);
        return row;
      } catch (error) {
        const row = { contractType, duration, ok: false, error: printableError(error) };
        results.durationProbes.push(row);
        return row;
      }
    }

    for (const contractType of types) {
      await probeDuration(contractType, 10);
      await probeDuration(contractType, 11);
    }

    // Find the supported upper tick boundary from proposals, not assumptions. If 11 ticks is
    // allowed, expand upward until a rejection (up to 1000), then binary-search the boundary.
    results.durationBounds = {};
    for (const contractType of types) {
      const one = proposalResults.get(contractType);
      if (!one?.ok) {
        results.durationBounds[contractType] = { minTickAccepted: false, maxTick: null, firstRejectedTick: null, resolved: false };
        continue;
      }
      let low = 1;
      let high = null;
      const ten = results.durationProbes.find((item) => item.contractType === contractType && item.duration === 10);
      const eleven = results.durationProbes.find((item) => item.contractType === contractType && item.duration === 11);
      if (ten?.ok) low = 10;
      else high = 10;
      if (eleven?.ok) {
        low = 11;
        high = null;
      } else if (!ten?.ok) {
        high = 10;
      } else {
        high = 11;
      }
      const expansion = [20, 50, 100, 250, 500, 1000];
      if (high === null) {
        for (const candidate of expansion) {
          const probe = await probeDuration(contractType, candidate);
          if (probe.ok) low = candidate;
          else { high = candidate; break; }
        }
      }
      if (high !== null && high > low + 1) {
        while (high - low > 1) {
          const mid = Math.floor((low + high) / 2);
          const probe = await probeDuration(contractType, mid);
          if (probe.ok) low = mid;
          else high = mid;
        }
      }
      results.durationBounds[contractType] = {
        minTickAccepted: true,
        maxTick: high === null ? null : low,
        firstRejectedTick: high,
        resolved: high !== null,
        note: high === null ? 'No rejected duration found up to 1000 ticks; maximum unresolved.' : null,
      };
      console.log(`${contractType} observed duration range: min=1 tick; ${high === null ? 'maximum unresolved after 1000-tick probe' : `max=${low} ticks (duration ${high} rejected)`}`);
    }

    const evenProposal = proposalResults.get('DIGITEVEN');
    if (!evenProposal?.ok || !evenProposal.proposalIdPresent || !Number.isFinite(evenProposal.askPrice)) {
      console.log('\nDIGITEVEN $1 proposal was not available; the script will not attempt any purchase.');
      results.demoTrade = { attempted: false, reason: 'No valid one-tick DIGITEVEN proposal available for the $1 demo trade.' };
    } else {
      section('8. One explicitly confirmed $1 DEMO trade');
      console.log(`Selected account type: ${String(account.account_type ?? account.type).toUpperCase()}`);
      console.log(`Market: R_100 | Contract: DIGITEVEN | Duration: 1 tick | Stake: ${currency} 1.00`);
      console.log('This is a real Deriv demo contract; it is not a simulated result.');
      console.log('The only buy in this spike happens after the exact confirmation below.');
      const confirmation = await ask('Type BUY DEMO CONTRACT to place it, or press Enter to skip: ');
      if (confirmation !== 'BUY DEMO CONTRACT') {
        results.demoTrade = { attempted: false, reason: 'User did not enter the exact confirmation phrase.' };
      } else {
        const startedAt = Math.floor(Date.now() / 1000);
        let buyResponse;
        try {
          buyResponse = await rpc.request({
            buy: evenProposal.proposalId,
            price: evenProposal.askPrice,
          }, 5000);
          printJson('Buy response', buyResponse, [token]);
        } catch (error) {
          console.log(`Buy reply was not received: ${printableError(error)}. No second buy will be sent.`);
        }

        let contractId = buyResponse?.buy?.contract_id;
        if (!contractId) {
          // A lost acknowledgement is treated as unknown; reconcile portfolio and never buy again.
          try {
            const portfolio = await rpc.request({ portfolio: 1 }, 10000);
            printJson('Portfolio reconciliation after missing buy acknowledgement', portfolio, [token]);
            const contracts = portfolio?.portfolio?.contracts ?? [];
            const candidate = contracts.find((item) => Number(item?.date_start ?? 0) >= startedAt && item?.contract_id);
            contractId = candidate?.contract_id;
            if (contractId) results.demoTrade.adoptedFromPortfolio = true;
          } catch (error) {
            console.log(`Portfolio reconciliation failed: ${printableError(error)}`);
          }
        }

        if (!contractId) {
          results.demoTrade = {
            attempted: true,
            status: 'unknown',
            buyReplyReceived: Boolean(buyResponse),
            noRetryPerformed: true,
            reason: 'No contract ID could be confirmed; stopped without retrying the buy.',
          };
        } else {
          results.demoTrade = {
            attempted: true,
            market: 'R_100',
            contractType: 'DIGITEVEN',
            duration: 1,
            stake: 1,
            currency,
            contractId,
            buyReplyReceived: Boolean(buyResponse),
            status: 'monitoring',
          };
          section(`9. Monitor contract ${contractId} until Deriv settles it`);
          let settledMessage = null;
          try {
            const first = await rpc.request({ proposal_open_contract: 1, contract_id: contractId, subscribe: 1 }, 15000);
            printJson('Initial proposal_open_contract response', first, [token]);
            if (first?.proposal_open_contract?.is_sold === 1 || first?.proposal_open_contract?.is_sold === true) {
              settledMessage = first;
            } else if (first.error) {
              throw new Error(`${first.error.code ?? 'Deriv error'}: ${first.error.message ?? 'open-contract subscription rejected'}`);
            } else {
              settledMessage = await new Promise((resolveSettlement, rejectSettlement) => {
                const timer = setTimeout(() => {
                  off();
                  rejectSettlement(new Error('Timed out waiting for is_sold=true. Reopen the account and reconcile before any further purchase.'));
                }, 120000);
                const off = rpc.onMessage((message) => {
                  if (message?.msg_type !== 'proposal_open_contract') return;
                  if (Number(message?.proposal_open_contract?.contract_id) !== Number(contractId)) return;
                  printJson('proposal_open_contract update', message, [token]);
                  if (message.proposal_open_contract?.is_sold === 1 || message.proposal_open_contract?.is_sold === true) {
                    clearTimeout(timer);
                    off();
                    resolveSettlement(message);
                  }
                });
              });
            }
          } catch (error) {
            results.demoTrade.status = 'monitoring_incomplete';
            results.demoTrade.monitoringError = printableError(error);
            results.demoTrade.noSecondBuy = true;
          }

          if (settledMessage?.proposal_open_contract) {
            const p = settledMessage.proposal_open_contract;
            results.demoTrade = {
              ...results.demoTrade,
              status: p.is_sold ? 'settled' : 'not_settled',
              isSold: Boolean(p.is_sold),
              profit: p.profit === undefined ? null : Number(p.profit),
              sellPrice: p.sell_price === undefined ? null : Number(p.sell_price),
              buyPrice: p.buy_price === undefined ? null : Number(p.buy_price),
              entrySpot: p.entry_tick ?? p.entry_spot ?? null,
              exitSpot: p.exit_tick ?? p.exit_spot ?? null,
              exitDigit: p.exit_tick_display_value === undefined ? null : String(p.exit_tick_display_value).slice(-1),
              contractId: p.contract_id ?? contractId,
            };
            printJson('Final Deriv settlement fields', {
              contract_id: p.contract_id,
              is_sold: p.is_sold,
              profit: p.profit,
              sell_price: p.sell_price,
              buy_price: p.buy_price,
              entry_tick: p.entry_tick,
              exit_tick: p.exit_tick,
              exit_tick_display_value: p.exit_tick_display_value,
            }, [token]);
          }
        }
      }
    }

    section('10. Compare behavior with and without authorize message');
    console.log('All initial trade-path requests were made on the OTP-authenticated connection without authorize.');
    try {
      const authorizeResponse = await rpc.request({ authorize: token }, 10000);
      printJson('Optional authorize-message response after trade checks (token redacted)', authorizeResponse, [token]);
      results.authorizationMessageProbe = {
        sentAfterInitialFlow: true,
        initialFlowUsedAuthorize: false,
        responseReceived: true,
        succeeded: !authorizeResponse.error,
        error: authorizeResponse.error ? { code: authorizeResponse.error.code ?? null, message: authorizeResponse.error.message ?? null } : null,
      };
    } catch (error) {
      results.authorizationMessageProbe = {
        sentAfterInitialFlow: true,
        initialFlowUsedAuthorize: false,
        responseReceived: false,
        error: printableError(error),
      };
      console.log(`The optional authorize probe did not complete: ${printableError(error)}`);
    }
  } finally {
    await rpc.close();
  }
}

function summarize(report) {
  const oneTickProposals = report.proposals.map((item) => ({
    contractType: item.contractType,
    ok: item.ok,
    error: item.error ?? null,
    askPriceType: item.askPriceType ?? null,
    payoutType: item.payoutType ?? null,
    commissionType: item.commissionType ?? null,
  }));
  return {
    generatedAt: new Date().toISOString(),
    apiBase: report.apiBase,
    oauth: report.oauth,
    accounts: report.accounts,
    otp: report.otp,
    websocket: report.websocket,
    symbols: report.symbols,
    ticks: report.ticks,
    contractsFor: report.contractsFor,
    proposals: oneTickProposals,
    durationProbes: report.durationProbes,
    durationBounds: report.durationBounds ?? {},
    authorizationMessageProbe: report.authorizationMessageProbe,
    demoTrade: report.demoTrade,
    notes: report.notes,
    phase0Passed: Boolean(
      report.oauth?.accessTokenReceived &&
      report.accounts?.ok &&
      report.otp?.ok &&
      report.websocket?.connected &&
      Object.values(report.ticks).filter((item) => item?.passed).length === 2 &&
      report.contractsFor?.ok &&
      report.contractsFor?.digitOverAvailable &&
      report.proposals.filter((item) => item.ok).length === 6 &&
      ['DIGITMATCH', 'DIGITDIFF', 'DIGITEVEN', 'DIGITODD', 'DIGITOVER', 'DIGITUNDER'].every((type) => report.durationBounds?.[type]?.resolved) &&
      report.authorizationMessageProbe?.responseReceived &&
      report.demoTrade?.status === 'settled' &&
      report.demoTrade?.isSold === true &&
      report.demoTrade?.contractId
    ),
  };
}

try {
  await main();
} catch (error) {
  console.error(`\nSPIKE STOPPED SAFELY: ${printableError(error)}`);
  results.stoppedWithError = printableError(error);
} finally {
  results.finishedAt = new Date().toISOString();
  const summary = summarize(results);
  try {
    await mkdir(dirname(REPORT_PATH), { recursive: true });
    await writeFile(REPORT_PATH, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
    console.log(`\nSaved redacted Phase 0 summary to ${REPORT_PATH}`);
    console.log(`Phase 0 overall: ${summary.phase0Passed ? 'PASSED' : 'NOT YET PASSED'}`);
  } catch (error) {
    console.error(`Could not save the summary: ${printableError(error)}`);
  }
  rl.close();
  process.exitCode = summary.phase0Passed ? 0 : results.stoppedWithError ? 1 : 2;
}
