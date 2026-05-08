# Maxstream / uprot bypass — full setup guide

> 🇮🇹 Italian first · 🇬🇧 English version below

---

## 🇮🇹 Maxstream + uprot per CB01 / EuroStreaming

I siti italiani CB01, EuroStreaming, Animeunity (e simili) servono i loro stream Maxstream **dietro un layer di shortlink uprot.net** (path `/msf/`, `/msfi/`, `/msfld/`). uprot serve un captcha visuale a **4 cifre** che cambia ad ogni page load + cookie di sessione. Senza risolverlo, qualsiasi GET a `maxstream.video/uprots/<token>` diretto ritorna `Error (131) File id error`.

Questa versione di `maxstream.py` implementa la pipeline completa di bypass. **Tutto opt-in**: senza dipendenze extra il file si comporta come la versione precedente.

### Le 2 feature principali (DIVERSE ma COMPLEMENTARI)

#### Feature 1 — OCR per leggere il captcha

Quando serve risolvere un captcha live, l'extractor prova in cascata:

1. **ddddocr** (locale, primario) — ~50% rate sui captcha rumorosi
2. **tesseract** (locale, fallback) — +15-20% combinato
3. **Cloudflare Workers AI** (3°, opt-in) — Llama 4 Scout / Gemma 3 12B / LLaVA → ~80-90%

Si attiva con due env vars:

```bash
CF_WORKER_OCR_URL=https://easyproxy-ocr.tuoaccount.workers.dev
CF_WORKER_OCR_AUTH=segreto
```

Senza queste env, il 3° backend è disabilitato (zero overhead).

#### Feature 2 — Cache pre-warmer (opzionale, sblocca rate 100%)

Una volta risolto un URL uprot, il maxstream finale dura ~22h. Quindi:

1. Una task background prende una **lista curata di URL** e li risolve **preventivamente** (usando Feature 1 internamente)
2. Salva mapping `(uprot_url, season, episode) → maxstream_url` su file JSON con TTL 22h
3. Quando l'utente clicca play, `extract()` controlla la cache: HIT → ritorna in <100ms, niente captcha runtime

Questa feature **non è inclusa di default in questa PR** — è un servizio asincrono background che richiede di toccare l'application lifecycle. È comunque pre-cablato in `extract()` (basta importare `mediaflow_proxy.services.uprot_url_cache` se decidi di aggiungerlo). Per l'implementazione completa vedi il commit nel fork EasyProxy: https://github.com/Pieropapamonello/biscotti/blob/uprot-pipeline-v2/services/uprot_warmer.py

### Cosa è cambiato a livello di codice

| Bug pre-esistente | Fix |
|---|---|
| **Greedy regex catturava honeypot URL** `/uprots/123456789012` (12 cifre sequenziali = placeholder che uprot piazza in `<div display:none>` per detect bot) | `_strip_uprot_honeypots` rimuove prima `display:none` divs + commenti HTML; nuovo `_parse_uprot_html` cerca esplicitamente `id="buttok"` o testo CONTINUE, fallback su URL uprots/uprotem unico |
| **Direct GET su `maxstream.video/uprots/<token>` ritornava `Error 131`** perché il WAF maxstream onora il token solo via redirect chain da uprot.net | `_follow_uprots_chain` cammina la chain manualmente con curl_cffi (chrome131 impersonation, persistenza cookie, max 10 hop) finché atterra su `maxsun{N}.online/watchfree/...` o `maxstream.video/emvvv/<id>` |
| **Captcha era 3 cifre, ora è 4** — anche con OCR perfetto POSTavamo prefisso 3-char rifiutato da uprot | Validazione 3-OR-4 cifre, prompt CF Worker chiede `digits=4` |
| **Singolo POST con OCR sbagliato → fallimento** | `_solve_uprot_captcha` fa max 4 retry, ogni retry usa la NUOVA immagine captcha che uprot serve dopo POST sbagliata (non re-fa OCR sulla stessa) |

### Setup CF Worker AI (5 min, gratis)

Vedi sezione **English** sotto per gli step dettagliati.

### Verifica

Stack docker (mediaflow-proxy con questa patch + CF Worker AI):
- HIMYM `/msfld/q1qs49nidph5` S1E11/E13/E15 → tutti ✅ HTTP 200 con manifest m3u8 reale
- Senza CF Worker → ~50% rate (ddddocr+tesseract)
- Con CF Worker → ~80% rate live, 100% se l'URL è in cache pre-warmata

### Crediti

Tutto questo lavoro è **merito di Nello e del suo addon [NelloStream](https://github.com/vitouchiha/nello-stream)**. La pipeline (`_uprotBypassWithCookies`, `_extractMaxstreamVideo`, `_aiOcrDigits`, `_handleScheduledUprotRefresh`) viene direttamente dal suo `workers/cfworker.js`.

---

## 🇬🇧 Maxstream + uprot for CB01 / EuroStreaming

Italian sites CB01, EuroStreaming, Animeunity (and similar) serve their Maxstream streams **behind a uprot.net shortlink layer** (paths `/msf/`, `/msfi/`, `/msfld/`). uprot serves a **4-digit visual captcha** that changes per page-load + session cookie. Without solving it, any direct GET to `maxstream.video/uprots/<token>` returns `Error (131) File id error`.

This version of `maxstream.py` implements the full bypass pipeline. **All opt-in**: with no extra dependencies the file behaves like the previous version.

### The 2 main features (DIFFERENT but COMPLEMENTARY)

#### Feature 1 — OCR to read the captcha

When a live captcha solve is needed, the extractor tries in cascade:

1. **ddddocr** (local, primary) — ~50% rate on noisy captchas
2. **tesseract** (local, fallback) — +15-20% combined
3. **Cloudflare Workers AI** (3rd, opt-in) — Llama 4 Scout / Gemma 3 12B / LLaVA → ~80-90%

Activate with two env vars:

```bash
CF_WORKER_OCR_URL=https://easyproxy-ocr.youraccount.workers.dev
CF_WORKER_OCR_AUTH=secret
```

Without these env vars, the 3rd backend is disabled (zero overhead).

#### Feature 2 — Cache pre-warmer (optional, unlocks 100% rate)

Once a uprot URL is resolved, the final maxstream link lasts ~22h. So:

1. A background task takes a **curated list of URLs** and resolves them **preventively** (using Feature 1 internally)
2. Saves `(uprot_url, season, episode) → maxstream_url` mapping to JSON file with 22h TTL
3. When user clicks play, `extract()` checks the cache: HIT → returns in <100ms, no runtime captcha

This feature is **not bundled in this PR by default** — it's an async background service that needs to hook into the app lifecycle. It is, however, pre-wired in `extract()` (just import `mediaflow_proxy.services.uprot_url_cache` to use it). For the full implementation see the EasyProxy fork commit: https://github.com/Pieropapamonello/biscotti/blob/uprot-pipeline-v2/services/uprot_warmer.py

### Code-level changes

| Pre-existing bug | Fix |
|---|---|
| **Greedy regex captured honeypot URL** `/uprots/123456789012` (12 sequential digits = placeholder uprot plants inside `<div display:none>` to detect bots) | `_strip_uprot_honeypots` removes `display:none` divs + HTML comments first; new `_parse_uprot_html` looks explicitly for `id="buttok"` or CONTINUE text, falls back to unique uprots/uprotem URL |
| **Direct GET on `maxstream.video/uprots/<token>` returned `Error 131`** because the maxstream WAF only honours the token via the uprot.net redirect chain | `_follow_uprots_chain` walks the chain manually with curl_cffi (chrome131 impersonation, cookie persistence, max 10 hops) until landing on `maxsun{N}.online/watchfree/...` or `maxstream.video/emvvv/<id>` |
| **Captcha was 3 digits, now is 4** — even with perfect OCR we POSTed a 3-char prefix uprot rejected | Validate 3-OR-4 digit responses, ask CF Worker for `digits=4` |
| **Single POST with wrong OCR → fail** | `_solve_uprot_captcha` retries up to 4 times, each retry uses the NEW captcha image uprot serves after a wrong POST (not re-OCR the same image) |

### CF Worker AI setup (5 min, free)

#### 1. Cloudflare account

Free signup at https://dash.cloudflare.com (skip if you have one).

#### 2. Create the Worker

- Dashboard → **Workers & Pages** → **Create application**
- Name: `easyproxy-ocr` (or whatever)
- Click **Deploy**

#### 3. Paste the code

Open the Worker → **Edit code** and paste:

```javascript
// easyproxy-ocr Worker — Captcha OCR with CF Workers AI
// Endpoint: POST /?ocr=1[&digits=4]
//   Headers: x-worker-auth: <AUTH_TOKEN>, content-type: image/png
//   Body: PNG bytes

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'x-worker-auth, content-type' } });
    }

    const authToken = (env.AUTH_TOKEN || '').trim();
    if (authToken) {
      const provided = (request.headers.get('x-worker-auth') || url.searchParams.get('auth') || '').trim();
      if (provided !== authToken) return _json({ error: 'Unauthorized' }, 401);
    }

    if (url.searchParams.get('ocr') !== '1') return _json({ error: 'POST /?ocr=1 with PNG body' }, 400);
    if (request.method !== 'POST') return _json({ error: 'POST required' }, 405);
    if (!env?.AI) return _json({ error: 'AI binding not configured' }, 500);

    try {
      const buf = new Uint8Array(await request.arrayBuffer());
      if (buf.length === 0 || buf.length > 1024 * 1024) return _json({ error: `Invalid PNG size: ${buf.length}` }, 400);
      const expected = parseInt(url.searchParams.get('digits') || '4', 10);
      const digits = await _aiOcrDigits(env, buf, expected);
      if (!digits) return _json({ error: 'OCR failed' }, 422);
      return _json({ digits, method: 'ai', expected });
    } catch (e) {
      return _json({ error: `OCR error: ${e.message}` }, 500);
    }
  },
};

async function _aiOcrDigits(env, imageBytes, expectedDigits = 4) {
  const allAnswers = [];
  const b64 = btoa(String.fromCharCode.apply(null, imageBytes));

  const prompts = [
    `The image shows ${expectedDigits} digits in a captcha. Reply with ONLY the ${expectedDigits} digits, nothing else.`,
    `Read the ${expectedDigits} numbers (0-9) in this image left to right. Output ONLY ${expectedDigits} digits, no other characters.`,
    `Extract the ${expectedDigits} digits from this captcha. Reply with the ${expectedDigits} digits only.`,
  ];

  const runOne = async (prompt) => {
    for (const model of ['@cf/meta/llama-4-scout-17b-16e-instruct', '@cf/google/gemma-3-12b-it', '@cf/meta/llama-3.2-11b-vision-instruct']) {
      try {
        const resp = await env.AI.run(model, { messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: `data:image/png;base64,${b64}` } }, { type: 'text', text: prompt }] }], max_tokens: 20 });
        const text = (resp?.response || '').replace(/[^0-9]/g, '');
        if (text) return text;
      } catch { /* try next */ }
    }
    return '';
  };

  const results = await Promise.allSettled(prompts.map(runOne));
  for (const r of results) if (r.status === 'fulfilled' && r.value) allAnswers.push(r.value);
  if (!allAnswers.length) return null;

  const exact = allAnswers.filter(a => a.length === expectedDigits);
  if (exact.length) {
    const freq = {};
    for (const a of exact) freq[a] = (freq[a] || 0) + 1;
    return Object.entries(freq).sort((a, b) => b[1] - a[1])[0][0];
  }
  return null;
}

function _json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
}
```

Click **Deploy**.

#### 4. Enable Workers AI binding

- Worker → **Settings → Bindings → Add binding → Workers AI**
- Variable name: `AI`
- Save & redeploy

#### 5. Set AUTH_TOKEN

- Worker → **Settings → Variables and Secrets → Add variable**
- Name: `AUTH_TOKEN`, Type: Secret, Value: a secret of your choice
- Save & redeploy

#### 6. Configure mediaflow-proxy

```yaml
environment:
  - CF_WORKER_OCR_URL=https://easyproxy-ocr.youraccount.workers.dev
  - CF_WORKER_OCR_AUTH=yoursecret
```

Restart mediaflow-proxy. Done.

### Free tier limits

| Resource | Free quota | Notes |
|---|---|---|
| Requests/day | 100,000 | plenty |
| Workers AI (Llama/Gemma) | ~10,000 neurons/day | ~3,000 captchas/day |

For personal use the free tier is enough. Beyond that, $5/month paid plan.

### Behavior if Worker offline / AI fails

mediaflow-proxy auto-falls back to `ddddocr` + `tesseract` (~50% rate). Never crashes, never blocks. The CF Worker OCR is purely additive.

### Verification

Docker stack (mediaflow-proxy with this patch + CF Worker AI):
- HIMYM `/msfld/q1qs49nidph5` S1E11/E13/E15 → all ✅ HTTP 200 with real m3u8 manifest
- Without CF Worker → ~50% rate (ddddocr+tesseract)
- With CF Worker → ~80% rate live, 100% if URL is in pre-warmed cache

### Credits

All this work is thanks to **Nello** and his addon [**NelloStream**](https://github.com/vitouchiha/nello-stream). The pipeline (`_uprotBypassWithCookies`, `_extractMaxstreamVideo`, `_aiOcrDigits`, `_handleScheduledUprotRefresh`) comes directly from his `workers/cfworker.js`.
