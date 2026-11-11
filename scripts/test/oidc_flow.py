#!/usr/bin/env python3
"""Test runner (runs INSIDE a container of the test pod; standard library only).

Phase 'kanidm': through Zentinel set up a person, a group and an OAuth2 client in Kanidm, then do a real OIDC
authorisation-code flow with PKCE as that person and check the id_token claims and userinfo.
Phase 'tuwunel': sign in to Tuwunel through single sign-on with Kanidm and get a Matrix access token.

Secrets (ADR 0054): this script creates the person's password and reads the admin password from the environment; it
never prints, logs or writes them except to the run-time tmpfs volume (/tls) that the test deletes. Output: PASS/FAIL lines only.
"""
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import secrets
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

IDM = os.environ.get("IDM_URL", "")          # https://idm.test.local:9443 (through Zentinel)
MATRIX = os.environ.get("MATRIX_URL", "http://localhost:8008")
STATE = "/tls"                        # tmpfs volume, removed by the test
CTX = ssl.create_default_context(cafile=f"{STATE}/ca.pem") if os.path.exists(f"{STATE}/ca.pem") else ssl.create_default_context()
FAILED = []


def result(name, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + name + (f" ({extra})" if extra and not ok else ""), flush=True)
    if not ok:
        FAILED.append(name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def call(method, url, body=None, headers=None, jar=None, follow=False):
    h = {"Accept": "application/json"}
    h.update(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    handlers = [urllib.request.HTTPSHandler(context=CTX)]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    if not follow:
        handlers.append(NoRedirect())
    op = urllib.request.build_opener(*handlers)
    try:
        r = op.open(urllib.request.Request(url, data=data, method=method, headers=h), timeout=30)
    except urllib.error.HTTPError as e:
        r = e
    raw = r.read()
    try:
        js = json.loads(raw) if raw else None
    except ValueError:
        js = None
    return r.status, {k.lower(): v for k, v in r.headers.items()}, js, raw


def totp_code(secret, algo="sha1", digits=6, step=30, now=None):
    """RFC 6238 (HOTP, RFC 4226, over the time counter). Returns (code string, counter)."""
    counter = int((time.time() if now is None else now) // step)
    mac = hmac.new(secret, struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    off = mac[-1] & 0x0F
    num = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(num).zfill(digits), counter


def fresh_totp(factor):
    """A code for a time step not used before (a server refuses to accept the same step twice)."""
    while True:
        code, counter = totp_code(bytes(factor["secret"]), factor["algo"], factor["digits"], factor["step"])
        if counter > factor.get("last", -1):
            factor["last"] = counter
            return code
        time.sleep(1)


def auth(user, password, privileged=False, factor=None):
    s, h, js, _ = call("POST", f"{IDM}/v1/auth", {"step": {"init2": {"username": user, "issue": "token", "privileged": privileged}}})
    sid = h.get("x-kanidm-auth-session-id")
    if not sid:
        return None
    hdr = {"X-KANIDM-AUTH-SESSION-ID": sid}
    mechs = ((js or {}).get("state") or {}).get("choose", [])
    mech = "passwordmfa" if "passwordmfa" in mechs else ("password" if "password" in mechs else (mechs[0] if mechs else "password"))
    s, h, js, _ = call("POST", f"{IDM}/v1/auth", {"step": {"begin": mech}}, hdr)
    for _i in range(4):
        state = (js or {}).get("state") or {}
        if "success" in state:
            return state["success"]
        if "denied" in state or "continue" not in state:
            return None
        allowed = state["continue"]
        if "password" in allowed:
            cred = {"password": password}
        elif "totp" in allowed and factor:
            cred = {"totp": int(fresh_totp(factor))}
        else:
            return None
        s, h, js, _ = call("POST", f"{IDM}/v1/auth", {"step": {"cred": cred}}, hdr)
    return None


def selftest():
    """RFC 6238 appendix B vectors (SHA1/256/512, 8 digits). No server needed."""
    vec = [("sha1", b"12345678901234567890", 59, "94287082"), ("sha256", b"12345678901234567890123456789012", 59, "46119246"),
           ("sha512", b"1234567890123456789012345678901234567890123456789012345678901234", 59, "90693936"),
           ("sha1", b"12345678901234567890", 1111111109, "07081804")]
    ok = all(totp_code(k, a, 8, 30, now=t)[0] == want for a, k, t, want in vec)
    result("RFC 6238 test vectors", ok)


def api(method, path, tok, body=None):
    return call(method, f"{IDM}{path}", body, {"Authorization": f"Bearer {tok}"})


def phase_kanidm():
    admin = auth("idm_admin", os.environ["KANIDM_ADMIN_PW"], privileged=True)
    result("login as idm_admin through Zentinel", bool(admin))
    if not admin:
        return
    api("POST", "/v1/group", admin, {"attrs": {"name": ["testers"]}})
    s, *_ = api("POST", "/v1/person", admin, {"attrs": {"name": ["tester"], "displayname": ["Test Person"], "mail": ["tester@test.local"]}})
    result("create person", s in (200, 201), s)
    s, *_ = api("POST", "/v1/group/testers/_attr/member", admin, ["tester"])
    result("add person to group", s in (200, 201), s)
    # set the person's password and a TOTP factor through a credential update session (Kanidm requires MFA for persons).
    # Password and TOTP secret are generated/handled only in this process and in the run-time tmpfs directory; never printed.
    s, _, js, _ = api("GET", "/v1/person/tester/_credential/_update", admin)
    sess = js[0] if js else None
    pw = secrets.token_urlsafe(24)
    s1, _, st, _ = api("POST", "/v1/credential/_update", admin, [{"password": pw}, sess])
    s2, _, st, _ = api("POST", "/v1/credential/_update", admin, ["totpgenerate", sess])
    tc = ((st or {}).get("mfaregstate") or {}).get("TotpCheck")
    factor = None
    if tc:
        factor = {"secret": tc["secret"], "algo": tc["algo"], "step": tc["step"], "digits": tc["digits"]}
        s3, _, st, _ = api("POST", "/v1/credential/_update", admin, [{"totpverify": [int(fresh_totp(factor)), "fs-test"]}, sess])
        if (st or {}).get("mfaregstate") == "TotpInvalidSha1" or "TotpInvalidSha1" in json.dumps((st or {}).get("mfaregstate")):
            api("POST", "/v1/credential/_update", admin, ["totpacceptsha1", sess])
            s3, _, st, _ = api("POST", "/v1/credential/_update", admin, [{"totpverify": [int(fresh_totp(factor)), "fs-test"]}, sess])
    s4, *_ = api("POST", "/v1/credential/_commit", admin, sess)
    result("set person credential (password + TOTP)", s1 == 200 and s2 == 200 and bool(factor) and s4 == 200, f"{s1}/{s2}/{s4}")
    if not factor:
        return
    open(f"{STATE}/.tester", "w").write(json.dumps({"pw": pw, "factor": factor}))
    os.chmod(f"{STATE}/.tester", 0o600)
    redirect = os.environ.get("TUWUNEL_CALLBACK", "http://localhost:8008/_matrix/client/unstable/login/sso/callback/tuwunel")
    s, *_ = api("POST", "/v1/oauth2/_basic", admin, {"attrs": {"name": ["tuwunel"], "displayname": ["Tuwunel"],
                "oauth2_rs_origin": [redirect], "oauth2_rs_origin_landing": ["http://localhost:8008/"]}})
    result("create OAuth2 client", s in (200, 201), s)
    s, *_ = api("POST", "/v1/oauth2/tuwunel/_scopemap/testers", admin, ["openid", "profile", "email"])
    result("scope map", s in (200, 201), s)
    s, _, sec, _ = api("GET", "/v1/oauth2/tuwunel/_basic_secret", admin)
    result("read client secret", s == 200 and isinstance(sec, str))
    if isinstance(sec, str):
        open(f"{STATE}/oidc-secret", "w").write(sec)
        os.chmod(f"{STATE}/oidc-secret", 0o644)
    # discovery through Zentinel
    s, _, disc, _ = call("GET", f"{IDM}/oauth2/openid/tuwunel/.well-known/openid-configuration")
    result("OIDC discovery through Zentinel", s == 200 and disc and disc.get("issuer", "").endswith("/oauth2/openid/tuwunel"))
    # real authorisation-code flow with PKCE as the person
    user = auth("tester", pw, factor=factor)
    result("login as tester (password + TOTP)", bool(user))
    if not user:
        return
    ver = secrets.token_urlsafe(48)
    chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
    nonce = secrets.token_urlsafe(12)
    q = urllib.parse.urlencode({"response_type": "code", "client_id": "tuwunel", "redirect_uri": redirect, "scope": "openid profile email",
                                "state": "s1", "nonce": nonce, "code_challenge": chal, "code_challenge_method": "S256"})
    s, _, js, _ = call("GET", f"{IDM}/oauth2/authorise?{q}", headers={"Authorization": f"Bearer {user}"})
    consent = (js or {}).get("ConsentRequested") or (js or {}).get("consentrequested")
    result("authorise request (consent asked)", s == 200 and bool(consent), s)
    if not consent:
        return
    s, h, _, _ = call("GET", f"{IDM}/oauth2/authorise/permit?token={urllib.parse.quote(consent['consent_token'])}", headers={"Authorization": f"Bearer {user}"})
    loc = h.get("location") or h.get("Location") or ""
    s2, h2, js2, _ = (s, h, None, None)
    if not loc:
        s, h, js3, _ = call("POST", f"{IDM}/oauth2/authorise/permit", {"consent_token": consent["consent_token"]}, {"Authorization": f"Bearer {user}"})
        loc = h.get("location") or h.get("Location") or ""
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [None])[0]
    result("permit gives a code on the registered redirect", bool(code) and loc.startswith(redirect))
    if not code:
        return
    basic = base64.b64encode(f"tuwunel:{sec}".encode()).decode()
    form = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "code_verifier": ver}).encode()
    s, _, tok, _ = call("POST", f"{IDM}/oauth2/token", form, {"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"})
    idt = (tok or {}).get("id_token")
    result("token exchange returns id_token and access_token", s == 200 and bool(idt) and bool((tok or {}).get("access_token")), s)
    if not idt:
        return
    seg = idt.split(".")
    claims = json.loads(base64.urlsafe_b64decode(seg[1] + "=" * (-len(seg[1]) % 4)))
    hdr = json.loads(base64.urlsafe_b64decode(seg[0] + "=" * (-len(seg[0]) % 4)))
    result("id_token claims (iss, aud, nonce) and ES256", claims.get("iss", "").endswith("/oauth2/openid/tuwunel") and claims.get("aud") == "tuwunel"
           and claims.get("nonce") == nonce and hdr.get("alg") == "ES256", hdr.get("alg"))
    s, _, ui, _ = call("GET", f"{IDM}/oauth2/openid/tuwunel/userinfo", headers={"Authorization": f"Bearer {tok['access_token']}"})
    result("userinfo for the person", s == 200 and (ui or {}).get("sub") == claims.get("sub"), s)


def phase_tuwunel():
    saved = json.load(open(f"{STATE}/.tester"))
    pw, factor = saved["pw"], saved["factor"]
    s, _, js, _ = call("GET", f"{MATRIX}/_matrix/client/v3/login")
    flows = (js or {}).get("flows", [])
    sso = [f for f in flows if f.get("type") == "m.login.sso"]
    result("Tuwunel offers m.login.sso", s == 200 and bool(sso), s)
    if not sso:
        return
    jar = http.cookiejar.CookieJar()
    back = "http://localhost:3000/after"
    s, h, _, _ = call("GET", f"{MATRIX}/_matrix/client/v3/login/sso/redirect/tuwunel?redirectUrl={urllib.parse.quote(back)}", jar=jar)
    loc = h.get("location") or h.get("Location") or ""
    result("Tuwunel redirects to Kanidm authorise", s in (302, 303, 307) and "/oauth2/" in loc, s)
    if "/oauth2/" not in loc:
        return
    user = auth("tester", pw, factor=factor)
    u = urllib.parse.urlparse(loc)
    s, _, js, _ = call("GET", f"{IDM}{u.path}?{u.query}", headers={"Authorization": f"Bearer {user}"})
    consent = (js or {}).get("ConsentRequested") or (js or {}).get("consentrequested")
    if consent:
        s, h, _, _ = call("GET", f"{IDM}/oauth2/authorise/permit?token={urllib.parse.quote(consent['consent_token'])}", headers={"Authorization": f"Bearer {user}"})
        loc2 = h.get("location") or h.get("Location") or ""
    else:
        loc2 = ""
    result("Kanidm sends the browser back to Tuwunel with a code", loc2.startswith(MATRIX) or "/sso/callback/" in loc2, s)
    if not loc2:
        return
    s, h, _, _ = call("GET", loc2.replace("http://localhost:8008", MATRIX), jar=jar)
    final = h.get("location") or h.get("Location") or ""
    ltok = urllib.parse.parse_qs(urllib.parse.urlparse(final).query).get("loginToken", [None])[0]
    result("Tuwunel callback accepts the code and issues a loginToken", bool(ltok), s)
    if not ltok:
        return
    s, _, js, _ = call("POST", f"{MATRIX}/_matrix/client/v3/login", {"type": "m.login.token", "token": ltok})
    result("Matrix login with the SSO token gives an access token", s == 200 and bool((js or {}).get("access_token")) and (js or {}).get("user_id", "").startswith("@"), s)


if __name__ == "__main__":
    {"kanidm": phase_kanidm, "tuwunel": phase_tuwunel, "selftest": selftest}[sys.argv[1]]()
    sys.exit(1 if FAILED else 0)
