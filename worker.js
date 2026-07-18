// Access gate for /arrive and /arrivethesis.
// Server-side allowlist: visitor enters a mobile number; if it is in the
// APPROVED_NUMBERS secret, a signed cookie is set and the page is served.
// Approved numbers live in a Cloudflare secret, never in this file.

const COOKIE = "arrive_gate";
const MAX_AGE = 30 * 24 * 60 * 60; // 30 days
const PROTECTED = [/^\/arrive(\/|$)/, /^\/arrivethesis(\/|$)/];

const isProtected = (p) => PROTECTED.some((re) => re.test(p));

// Keep only digits; drop country code / leading zero -> last 10 digits (India).
function normalize(raw) {
  const d = String(raw || "").replace(/\D/g, "");
  return d.length > 10 ? d.slice(-10) : d;
}

function approvedSet(env) {
  const set = new Set();
  for (const tok of String(env.APPROVED_NUMBERS || "").split(/\D+/)) {
    if (!tok) continue;
    const n = tok.length > 10 ? tok.slice(-10) : tok;
    if (n.length === 10) set.add(n);
  }
  return set;
}

const b64url = {
  enc: (s) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  dec: (s) => atob(s.replace(/-/g, "+").replace(/_/g, "/")),
};

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  let s = "";
  new Uint8Array(sig).forEach((b) => (s += String.fromCharCode(b)));
  return b64url.enc(s);
}

async function makeToken(env, number) {
  const payload = b64url.enc(JSON.stringify({ n: number, exp: Date.now() + MAX_AGE * 1000 }));
  return payload + "." + (await hmac(env.GATE_SECRET, payload));
}

async function validToken(env, token) {
  if (!token || token.indexOf(".") < 0) return false;
  const [payload, sig] = token.split(".");
  const expected = await hmac(env.GATE_SECRET, payload);
  if (sig !== expected) return false;
  try {
    const data = JSON.parse(b64url.dec(payload));
    return !!data.exp && Date.now() < data.exp;
  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const m = (request.headers.get("Cookie") || "").match(
    new RegExp("(?:^|; )" + name + "=([^;]+)")
  );
  return m ? decodeURIComponent(m[1]) : null;
}

function gatePage({ error } = {}) {
  const errBanner = error
    ? `<div class="err">That number isn't on the approved list. Please use the number your invite was sent to, or ask for access.</div>`
    : "";
  const html = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Arrive — Private access</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='22' fill='%23141a24'/%3E%3Ctext x='50' y='73' font-family='Georgia,serif' font-size='66' font-weight='700' text-anchor='middle' fill='%23e07a2b'%3EA%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px;
    font-family:"Inter",system-ui,sans-serif;color:#fff;
    background:radial-gradient(900px 520px at 78% -8%,rgba(224,122,43,.18),transparent 60%),
      radial-gradient(760px 520px at 10% 110%,rgba(43,95,138,.20),transparent 60%),
      linear-gradient(160deg,#0f1826,#16233a 55%,#111a2b);}
  .card{width:100%;max-width:420px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.12);
    border-radius:22px;padding:34px 30px;backdrop-filter:blur(6px);
    box-shadow:0 30px 80px rgba(0,0,0,.35)}
  .wm{font-family:"Bricolage Grotesque",sans-serif;font-weight:800;font-size:26px;letter-spacing:-.02em;text-align:center}
  .wm b{color:#e07a2b}.wm sup{font-size:.42em;font-weight:600;opacity:.75;margin-left:1px}
  .lock{display:flex;align-items:center;justify-content:center;gap:7px;margin-top:14px;
    font-size:10.5px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:rgba(255,255,255,.5)}
  h1{font-family:"Bricolage Grotesque",sans-serif;font-weight:700;font-size:23px;line-height:1.15;
    letter-spacing:-.015em;margin-top:20px;text-align:center}
  p.sub{font-size:13.5px;line-height:1.55;color:rgba(255,255,255,.66);margin-top:10px;text-align:center}
  form{margin-top:22px}
  .field{display:flex;align-items:center;gap:0;background:rgba(255,255,255,.06);
    border:1px solid rgba(255,255,255,.16);border-radius:13px;overflow:hidden;transition:border-color .18s}
  .field:focus-within{border-color:#e07a2b}
  .field .cc{padding:0 12px;font-size:14.5px;font-weight:600;color:rgba(255,255,255,.55);border-right:1px solid rgba(255,255,255,.14);align-self:stretch;display:flex;align-items:center}
  .field input{flex:1;min-width:0;background:transparent;border:0;outline:0;color:#fff;
    font-family:inherit;font-size:15.5px;font-weight:500;padding:15px 14px;letter-spacing:.02em}
  .field input::placeholder{color:rgba(255,255,255,.38);font-weight:400}
  button{width:100%;margin-top:14px;border:0;border-radius:13px;background:#e07a2b;color:#fff;
    font-family:inherit;font-weight:700;font-size:14.5px;padding:15px;cursor:pointer;
    display:flex;align-items:center;justify-content:center;gap:8px;transition:background .18s,transform .18s}
  button:hover{background:#ec8636;transform:translateY(-1px)}
  .err{background:rgba(168,51,31,.22);border:1px solid rgba(168,51,31,.5);color:#ffb9a6;
    font-size:12.5px;line-height:1.45;border-radius:11px;padding:11px 13px;margin-top:20px}
  .foot{margin-top:20px;text-align:center;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:rgba(255,255,255,.32)}
</style></head>
<body>
  <div class="card">
    <div class="wm">Arri<b>v</b>e<sup>™</sup></div>
    <div class="lock">🔒 Private preview · by invitation</div>
    <h1>This preview is invitation-only</h1>
    <p class="sub">Enter the mobile number your invitation was sent to. Access is limited to approved numbers.</p>
    ${errBanner}
    <form method="POST" autocomplete="off">
      <div class="field">
        <span class="cc">+91</span>
        <input name="number" type="tel" inputmode="numeric" autocomplete="tel-national"
          placeholder="Mobile number" maxlength="15" required autofocus
          pattern="[0-9 +\\-]{6,15}" aria-label="Mobile number">
      </div>
      <button type="submit">Continue <span>&rarr;</span></button>
    </form>
    <div class="foot">Confidential · Arrive™ · Strategy &amp; Concept</div>
  </div>
</body></html>`;
  return new Response(html, {
    status: error ? 401 : 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // Defensive: anything not protected is served straight from assets.
      if (!isProtected(path)) return env.ASSETS.fetch(request);

      // Misconfiguration guard: if secrets are missing, don't lock everyone
      // out silently or, worse, let everyone in — show the gate.
      if (!env.GATE_SECRET || !env.APPROVED_NUMBERS) return gatePage({});

      // Submitting the number.
      if (request.method === "POST") {
        const form = await request.formData();
        const number = normalize(form.get("number"));
        if (number.length === 10 && approvedSet(env).has(number)) {
          const token = await makeToken(env, number);
          return new Response(null, {
            status: 303,
            headers: {
              Location: path,
              "Set-Cookie": `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${MAX_AGE}`,
            },
          });
        }
        return gatePage({ error: true });
      }

      // Already unlocked?
      if (await validToken(env, getCookie(request, COOKIE))) {
        return env.ASSETS.fetch(request);
      }
      return gatePage({});
    } catch (e) {
      // Never take the static site down because of a gate bug.
      try {
        return env.ASSETS.fetch(request);
      } catch {
        return new Response("Service unavailable", { status: 503 });
      }
    }
  },
};
