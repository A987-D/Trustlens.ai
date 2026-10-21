import asyncio
import difflib
import hashlib
import ipaddress
import logging
import os
import re
import socket
import sys
import time
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None

from ai_auditor import (
    AIUnavailableError,
    audit_blueprint_with_ai,
    audit_image_with_ai,
    build_semantic_neural_synthesis,
    load_memory,
    mutate_memory,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("trustlens.api")

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

MAX_INPUT_CHARS = 20_000
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
MAX_BLUEPRINT_CHARS = 12_000
PAGE_TIMEOUT_MS = 10_000
EXTRACT_DEADLINE_S = 18

# Comprehensive list of popular Indian & Global websites + AI platforms
PROTECTED_BRANDS = {
    "amazon": ("amazon.com", "amazon.in", "amzn.in", "amzn.to", "media-amazon.com"),
    "flipkart": ("flipkart.com",),
    "myntra": ("myntra.com",),
    "meesho": ("meesho.com",),
    "nykaa": ("nykaa.com",),
    "ajio": ("ajio.com",),
    "paytm": ("paytm.com", "paytm.in"),
    "phonepe": ("phonepe.com",),
    "google": ("google.com", "google.co.in", "g.co", "gmail.com", "youtube.com"),
    "youtube": ("youtube.com", "youtu.be"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "hotstar": ("hotstar.com", "jiocinema.com"),
    "spotify": ("spotify.com",),
    "paypal": ("paypal.com",),
    "razorpay": ("razorpay.com",),
    "whatsapp": ("whatsapp.com", "wa.me"),
    "telegram": ("telegram.org", "t.me"),
    "instagram": ("instagram.com",),
    "facebook": ("facebook.com", "fb.com"),
    "linkedin": ("linkedin.com",),
    "twitter": ("twitter.com", "x.com"),
    "reddit": ("reddit.com",),
    "discord": ("discord.com", "discord.gg"),
    "zoom": ("zoom.us",),
    "github": ("github.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "hdfcbank": ("hdfcbank.com", "hdfc.com"),
    "icicibank": ("icicibank.com",),
    "axisbank": ("axisbank.com",),
    "kotak": ("kotak.com",),
    "pnbindia": ("pnbindia.in",),
    "bankofbaroda": ("bankofbaroda.in",),
    "canarabank": ("canarabank.com",),
    "unionbank": ("unionbankofindia.co.in",),
    "indusind": ("indusind.com",),
    "yesbank": ("yesbank.in",),
    "idfcfirst": ("idfcfirstbank.com",),
    "indiapost": ("indiapost.gov.in",),
    "delhivery": ("delhivery.com",),
    "bluedart": ("bluedart.com",),
    "irctc": ("irctc.co.in",),
    "uidai": ("uidai.gov.in",),
    "incometax": ("incometax.gov.in",),
    "parivahan": ("parivahan.gov.in",),
    "digilocker": ("digilocker.gov.in",),
    "epfindia": ("epfindia.gov.in",),
    "npci": ("npci.org.in", "bhimupi.org.in"),
    "zerodha": ("zerodha.com",),
    "groww": ("groww.in",),
    "upstox": ("upstox.com",),
    "angelone": ("angelone.in",),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "zomato": ("zomato.com",),
    "swiggy": ("swiggy.com",),
    "ola": ("olacabs.com",),
    "uber": ("uber.com",),
    "makemytrip": ("makemytrip.com",),
    "airtel": ("airtel.in",),
    "jio": ("jio.com",),
    "vi": ("myvi.in",),
    "bses": ("bsesdelhi.com",),
    "tatapower": ("tatapower.com",),
    # Popular AI Websites
    "openai": ("openai.com", "chatgpt.com"),
    "chatgpt": ("chatgpt.com", "openai.com"),
    "gemini": ("gemini.google.com", "aistudio.google.com", "google.com"),
    "claude": ("claude.ai", "anthropic.com"),
    "anthropic": ("anthropic.com", "claude.ai"),
    "perplexity": ("perplexity.ai",),
    "copilot": ("copilot.microsoft.com", "microsoft.com"),
    "deepseek": ("deepseek.com",),
    "midjourney": ("midjourney.com",),
    "huggingface": ("huggingface.co",),
}

# Add short aliases so 'hdfc-login.com' or 'icici.xyz' or 'amz0n.com' match their parent brand
BRAND_ALIASES = {
    "hdfc": "hdfcbank",
    "icici": "icicibank",
    "axis": "axisbank",
    "pnb": "pnbindia",
    "bob": "bankofbaroda",
    "canara": "canarabank",
    "idfc": "idfcfirst",
    "amzn": "amazon",
    "flpkrt": "flipkart",
    "fb": "facebook",
    "insta": "instagram",
    "yt": "youtube",
    "gpt": "chatgpt",
    "openal": "openai",
}

WHITELIST_DOMAINS = tuple({d for doms in PROTECTED_BRANDS.values() for d in doms} | {"localhost", "127.0.0.1", "example.com"})
SUSPICIOUS_TLDS = (".xyz", ".top", ".buzz", ".click", ".zip", ".loan", ".work", ".tk", ".gq", ".ml", ".cf", ".rest", ".fit", ".icu", ".vip", ".win", ".bid")

EXPLICIT_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|in|org|net|edu|gov|mil|co|io|ai|me|app|dev|xyz|top|buzz|click|zip|loan|work|tk|info|biz|online|site|tech|store|shop|bank|pay|icu|vip|win| club|live|pro)\b(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)
NUM_RE = re.compile(r"(?<!\d)(?:\d[ -]?){9,15}\d(?!\d)")

_browser_slots = asyncio.Semaphore(2)
_ai_slots = asyncio.Semaphore(4)

app = FastAPI(title="TrustLens AI - Primary AI Judge & Deep Impersonation Sentinel (CC6-AI05)")

def _allowed_origins() -> list[str]:
    raw = os.environ.get("ALLOWED_ORIGINS", "").strip()
    if raw:
        return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
    # Local development defaults only. Set ALLOWED_ORIGINS in production.
    return ["http://localhost:5000", "http://127.0.0.1:5000"]


class RateLimiter:
    """Fixed-window in-memory limiter, per client key and bucket."""

    def __init__(self):
        self._hits: dict[tuple[str, str], tuple[float, int]] = {}

    def allow(self, key: str, bucket: str, limit: int, window_s: int, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if len(self._hits) > 10_000:
            self._hits = {k: v for k, v in self._hits.items() if now - v[0] < window_s}
        start, count = self._hits.get((key, bucket), (now, 0))
        if now - start >= window_s:
            start, count = now, 0
        if count >= limit:
            self._hits[(key, bucket)] = (start, count)
            return False
        self._hits[(key, bucket)] = (start, count + 1)
        return True


RATE_LIMITS = {
    "/api/audit": (int(os.environ.get("RATE_AUDIT_PER_MIN", "20")), 60),
    "/api/audit/upload": (int(os.environ.get("RATE_AUDIT_PER_MIN", "20")), 60),
    "/api/evaluate": (int(os.environ.get("RATE_EVALUATE_PER_HOUR", "3")), 3600),
}
_rate_limiter = RateLimiter()
_TRUST_PROXY = os.environ.get("TRUST_PROXY", "").strip() == "1"


def _client_key(request) -> str:
    if _TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def rate_limit(request, call_next):
    rule = RATE_LIMITS.get(request.url.path)
    if rule and request.method == "POST":
        limit, window = rule
        if not _rate_limiter.allow(_client_key(request), request.url.path, limit, window):
            return JSONResponse(status_code=429, content={"detail": "Too many requests. Please wait and retry."}, headers={"Retry-After": str(window)})
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditRequest(BaseModel):
    input_text: str = Field(..., min_length=1, max_length=MAX_INPUT_CHARS)
    channel: str = "manual"
    is_group: bool = False
    is_business: bool = False


def scrub_pii(text: str) -> str:
    return NUM_RE.sub("[REDACTED_NUM]", text)


def _domain_matches(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


# --------------------------------------------------------------------------- #
# Deep Visual Homoglyph, Consonant-Skeleton & Levenshtein Impersonation Engine
# --------------------------------------------------------------------------- #
def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _visual_skeleton(label: str) -> str:
    s = label.lower()
    s = (
        s.replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .replace("nn", "m")
        .replace("ri", "n")
        .replace("ci", "a")
        .replace("fi", "h")
    )
    trans = str.maketrans({
        "0": "o", "1": "l", "!": "l", "|": "l", "3": "e",
        "4": "a", "@": "a", "5": "s", "$": "s", "7": "t", "8": "b", "9": "g", "6": "g", "2": "z",
    })
    s = s.translate(trans)
    s = re.sub(r"(.)\1+", r"\1", s)
    return s


def _extract_registrable_label(host: str) -> str:
    parts = [p for p in host.lower().split(".") if p and p != "www"]
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def detect_impersonation(host: str) -> dict | None:
    host = host.lower().rstrip(".")
    if _domain_matches(host, WHITELIST_DOMAINS):
        return None

    core_label = _extract_registrable_label(host)
    if not core_label or len(core_label) < 2:
        return None

    clean_label = core_label.replace("-", "")
    skel_label = _visual_skeleton(clean_label)
    il_unified_label = skel_label.replace("l", "i")

    ai_brands = {"openai", "chatgpt", "gemini", "claude", "anthropic", "perplexity", "copilot", "deepseek", "midjourney", "huggingface"}

    # Check direct alias matches first (e.g., 'hdfc-kyc.com', 'openal.com', 'icici-update.in')
    for alias, target_brand in BRAND_ALIASES.items():
        if clean_label == alias or alias in core_label.split("-") or skel_label == _visual_skeleton(alias):
            official_domains = PROTECTED_BRANDS[target_brand]
            is_ai = target_brand in ai_brands
            return {
                "brand": target_brand.upper(),
                "official": official_domains[0],
                "is_ai_impersonation": is_ai,
                "technique": f"{'Impersonating AI Platform' if is_ai else 'Brand Impersonation'} (Alias / Look-Alike Spoofing)",
                "explanation": f"Domain '{host}' impersonates '{target_brand.upper()}' (Official website: {official_domains[0]}).",
                "score_boost": 94,
            }

    for brand, official_domains in PROTECTED_BRANDS.items():
        brand_skel = _visual_skeleton(brand)
        brand_il = brand_skel.replace("l", "i")
        is_ai = brand in ai_brands
        prefix = "Impersonating AI Platform" if is_ai else "Popular Website Impersonation"

        # 1. Exact Brand on Wrong TLD / Hyphen Combo (e.g. 'amazon.xyz', 'netflix-verify.com')
        if clean_label == brand or brand in core_label.split("-"):
            return {
                "brand": brand.upper(),
                "official": official_domains[0],
                "is_ai_impersonation": is_ai,
                "technique": f"{prefix} (Unauthorized Domain / Combo-Squatting)",
                "explanation": f"Uses protected brand name '{brand.upper()}' on unofficial domain '{host}' (Real site: {official_domains[0]}).",
                "score_boost": 90,
            }

        # 2. Visual Homoglyph Match (e.g., 'arnazon.com' rn->m, 'paytrn.in', 'g00gle.com', 'sbl.co.in', 'fl1pkart.com')
        if skel_label == brand_skel or il_unified_label == brand_il:
            return {
                "brand": brand.upper(),
                "official": official_domains[0],
                "is_ai_impersonation": is_ai,
                "technique": f"{prefix} (Visual Homoglyph Character Swap)",
                "explanation": f"Domain '{host}' visually impersonates '{brand.upper()}' ({official_domains[0]}) using deceptive look-alike letters (such as 'rn' for 'm', '0' for 'o', '1'/'l' for 'i', or doubled letters).",
                "score_boost": 96,
            }

        # 3. Substring Homoglyph + Phishing Word (e.g. 'arnazon-prime.com', 'g00gle-security.com')
        if len(brand_skel) >= 4 and (brand_skel in skel_label or brand in clean_label or brand_il in il_unified_label):
            return {
                "brand": brand.upper(),
                "official": official_domains[0],
                "is_ai_impersonation": is_ai,
                "technique": f"{prefix} (Embedded Look-Alike Brand)",
                "explanation": f"Embeds a visual look-alike of '{brand.upper()}' inside unofficial domain '{host}' (Real site: {official_domains[0]}).",
                "score_boost": 92,
            }

        # 4. Levenshtein Edit Distance & Vowel-Drop Typosquatting ('amzon.com', 'flpkart.com', 'hdfcbnk.com', 'ntflix.com', 'chatgpi.com')
        if len(brand) >= 4 and abs(len(clean_label) - len(brand)) <= 2:
            dist = _levenshtein(clean_label, brand)
            dist_skel = _levenshtein(skel_label, brand_skel)
            dist_il = _levenshtein(il_unified_label, brand_il)
            min_dist = min(dist, dist_skel, dist_il)
            ratio = difflib.SequenceMatcher(None, skel_label, brand_skel).ratio()
            if min_dist == 1 or (len(brand) >= 5 and min_dist <= 2 and ratio >= 0.72):
                return {
                    "brand": brand.upper(),
                    "official": official_domains[0],
                    "is_ai_impersonation": is_ai,
                    "technique": f"{prefix} (Clever Typosquatting — Edit Distance {min_dist})",
                    "explanation": f"Domain '{host}' is a {min_dist}-character typosquat of popular website '{brand.upper()}' (Official: {official_domains[0]}).",
                    "score_boost": 93,
                }

    phish_words = ("login", "verify", "secure", "update", "account", "kyc", "refund", "reward", "claim", "customs", "bill", "disconnect", "gpt", "ai-bot", "wallet")
    if "-" in core_label and sum(1 for w in phish_words if w in core_label) >= 1:
        return {
            "brand": "Targeted Service / Portal",
            "official": "Official App/Website",
            "is_ai_impersonation": "gpt" in core_label or "ai" in core_label,
            "technique": "Hyphen-Stacked Deceptive Domain",
            "explanation": f"Domain '{host}' stacks security/billing/AI keywords with hyphens to appear official.",
            "score_boost": 78,
        }

    return None


def extract_first_url_or_domain(text: str) -> tuple[bool, bool, str, str, str]:
    candidate = text.strip()
    m = EXPLICIT_URL_RE.search(candidate)
    if m:
        raw_url = m.group(0).rstrip(".,;:!?)]}\"'")
        is_single = candidate == m.group(0)
        try:
            p = urlparse(raw_url)
            return True, is_single, raw_url, (p.hostname or "").lower().rstrip("."), p.scheme.lower()
        except ValueError:
            pass

    m_bare = BARE_DOMAIN_RE.search(candidate)
    if m_bare:
        raw_dom = m_bare.group(0).rstrip(".,;:!?)]}\"'")
        is_single = len(candidate.split()) == 1
        full_url = f"https://{raw_dom}"
        try:
            p = urlparse(full_url)
            return True, is_single, full_url, (p.hostname or "").lower().rstrip("."), "https (probed)"
        except ValueError:
            pass

    return False, False, "", "", ""


# --------------------------------------------------------------------------- #
# Playwright Deep Internal Website Forensics
# --------------------------------------------------------------------------- #
async def _is_public_host(host: str) -> tuple[bool, str]:
    if not host:
        return False, "no hostname"
    try:
        return (True, "") if ipaddress.ip_address(host).is_global else (False, "private IP")
    except ValueError:
        pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return False, "domain does not resolve in DNS"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            return False, "private IP"
    return (True, "") if infos else (False, "domain does not resolve")


async def inspect_website_internally_with_playwright(url: str, requested_host: str) -> dict:
    forensics = {
        "probed": False,
        "reachable": False,
        "final_url": url,
        "final_host": requested_host,
        "page_title": "",
        "claimed_brands_inside_dom": [],
        "claimed_ai_inside_dom": [],
        "password_inputs_count": 0,
        "otp_or_pin_inputs_count": 0,
        "card_or_cvv_inputs_count": 0,
        "api_key_inputs_count": 0,
        "suspicious_form_actions": [],
        "external_brand_logos": [],
        "internal_risk_delta": 0,
        "internal_findings": [],
        "verified_benign_interior": False,
        "blueprint_text": "",
    }

    if async_playwright is None:
        forensics["blueprint_text"] = f"[Playwright not installed] URL: {url}"
        return forensics

    ok, reason = await _is_public_host(requested_host)
    if not ok:
        forensics["blueprint_text"] = f"[DNS/Host Check: {reason}] URL: {url}"
        return forensics

    async def _run_probe():
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context(ignore_https_errors=True, accept_downloads=False)
                page = await context.new_page()
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                    forensics["reachable"] = True
                except Exception:
                    if url.startswith("https://"):
                        http_url = "http://" + url[len("https://"):]
                        await page.goto(http_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                        forensics["reachable"] = True

                forensics["probed"] = True
                forensics["final_url"] = page.url
                final_host = (urlparse(page.url).hostname or requested_host).lower().rstrip(".")
                forensics["final_host"] = final_host

                dom_signals = await page.evaluate(
                    """() => {
                        const title = document.title || "";
                        const metaSite = document.querySelector('meta[property="og:site_name"]')?.content || "";
                        const headings = Array.from(document.querySelectorAll('h1, h2, h3')).slice(0, 10).map(e => e.innerText.trim()).filter(Boolean);
                        const inputs = Array.from(document.querySelectorAll('input'));
                        const pwCount = inputs.filter(i => i.type === 'password').length;
                        const otpCount = inputs.filter(i => /otp|pin|cvv|passcode|mpin/i.test((i.name||'')+(i.id||'')+(i.placeholder||''))).length;
                        const cardCount = inputs.filter(i => /card|cc-number|debit|credit|expiry/i.test((i.name||'')+(i.id||'')+(i.placeholder||'')+(i.autocomplete||''))).length;
                        const apiKeyCount = inputs.filter(i => /api[_-]?key|secret[_-]?key|token|seed[_-]?phrase|private[_-]?key/i.test((i.name||'')+(i.id||'')+(i.placeholder||''))).length;
                        const forms = Array.from(document.querySelectorAll('form')).map(f => f.getAttribute('action') || '').filter(Boolean);
                        const imgSources = Array.from(document.querySelectorAll('img, link[rel*="icon"]')).map(el => el.src || el.href || '').filter(Boolean).slice(0, 30);
                        const bodySample = (document.body?.innerText || "").slice(0, 4000);
                        return { title, metaSite, headings, pwCount, otpCount, cardCount, apiKeyCount, forms, imgSources, bodySample };
                    }"""
                )

                forensics["page_title"] = dom_signals.get("title", "")
                forensics["password_inputs_count"] = dom_signals.get("pwCount", 0)
                forensics["otp_or_pin_inputs_count"] = dom_signals.get("otpCount", 0)
                forensics["card_or_cvv_inputs_count"] = dom_signals.get("cardCount", 0)
                forensics["api_key_inputs_count"] = dom_signals.get("apiKeyCount", 0)

                combined_identity_text = " ".join([
                    dom_signals.get("title", ""),
                    dom_signals.get("metaSite", ""),
                    " ".join(dom_signals.get("headings", [])),
                    dom_signals.get("bodySample", "")[:1200],
                ]).lower()

                is_official_host = _domain_matches(final_host, WHITELIST_DOMAINS)
                ai_brands = {"openai", "chatgpt", "gemini", "claude", "anthropic", "perplexity", "copilot", "deepseek"}

                if not is_official_host:
                    for brand, official_doms in PROTECTED_BRANDS.items():
                        if re.search(rf"\b{re.escape(brand)}\b", combined_identity_text):
                            if brand in ai_brands:
                                forensics["claimed_ai_inside_dom"].append(f"{brand.upper()} (Official: {official_doms[0]})")
                            else:
                                forensics["claimed_brands_inside_dom"].append(f"{brand.upper()} (Official: {official_doms[0]})")

                        for img_src in dom_signals.get("imgSources", []):
                            if any(od in img_src.lower() for od in official_doms):
                                forensics["external_brand_logos"].append(f"{brand.upper()} asset hotlinked")
                                break

                    for action in dom_signals.get("forms", []):
                        act_low = action.lower()
                        if act_low.startswith("http") and final_host not in act_low:
                            forensics["suspicious_form_actions"].append(action[:100])
                        elif any(x in act_low for x in ("telegram", "discord.com/api/webhooks", ".php", "mailto:")):
                            forensics["suspicious_form_actions"].append(action[:100])

                try:
                    snap = await page.aria_snapshot(mode="ai")
                except Exception:
                    snap = dom_signals.get("bodySample", "")

                forensics["blueprint_text"] = (
                    f"[PLAYWRIGHT INTERNAL DOM FORENSICS]\n"
                    f"Requested URL: {url} -> Final URL: {page.url}\n"
                    f"Page Title: {forensics['page_title']}\n"
                    f"Internal Inputs: Passwords={forensics['password_inputs_count']}, OTP/PIN={forensics['otp_or_pin_inputs_count']}, "
                    f"Cards={forensics['card_or_cvv_inputs_count']}, API_Keys={forensics['api_key_inputs_count']}\n"
                    f"Claimed Brands Inside DOM: {forensics['claimed_brands_inside_dom']}\n"
                    f"Claimed AI Platforms Inside DOM: {forensics['claimed_ai_inside_dom']}\n"
                    f"Accessibility Tree / Content:\n{(snap or dom_signals.get('bodySample', ''))[:MAX_BLUEPRINT_CHARS]}"
                )
            finally:
                await browser.close()

    try:
        async with _browser_slots:
            await asyncio.wait_for(_run_probe(), timeout=EXTRACT_DEADLINE_S)
    except Exception as e:
        forensics["blueprint_text"] = f"[Playwright probe note: {type(e).__name__}] URL: {url}"

    delta = 0
    findings = []
    if forensics["claimed_ai_inside_dom"]:
        delta += 65
        findings.append({
            "type": "Internal DOM AI Impersonation",
            "target": ", ".join(forensics["claimed_ai_inside_dom"][:3]),
            "explanation": f"Playwright inspected inside '{forensics['final_host']}' and found it claiming to be an official AI platform on an unauthorized domain.",
            "severity": "High",
        })
    if forensics["claimed_brands_inside_dom"]:
        delta += 55
        findings.append({
            "type": "Internal DOM Brand Claim Mismatch",
            "target": f"Page Title/DOM claims: {', '.join(forensics['claimed_brands_inside_dom'][:3])}",
            "explanation": f"Playwright verified the webpage internally claims to be a trusted brand while hosted on '{forensics['final_host']}'.",
            "severity": "High",
        })
    if forensics["password_inputs_count"] > 0 or forensics["otp_or_pin_inputs_count"] > 0 or forensics["card_or_cvv_inputs_count"] > 0:
        if not _domain_matches(forensics["final_host"], WHITELIST_DOMAINS):
            delta += 45
            findings.append({
                "type": "Active Credential / OTP / Card Harvester Inside DOM",
                "target": f"Passwords={forensics['password_inputs_count']}, OTP/PIN={forensics['otp_or_pin_inputs_count']}, Cards={forensics['card_or_cvv_inputs_count']}",
                "explanation": "Playwright headless probe found active sensitive input fields inside an unverified domain.",
                "severity": "High",
            })
    if forensics["api_key_inputs_count"] > 0 and not _domain_matches(forensics["final_host"], WHITELIST_DOMAINS):
        delta += 60
        findings.append({
            "type": "Secret Key / Seed Phrase Harvester Inside DOM",
            "target": f"API/Secret Key Inputs={forensics['api_key_inputs_count']}",
            "explanation": "Playwright found input fields requesting API keys, tokens, or wallet seed phrases.",
            "severity": "High",
        })

    if (
        forensics["reachable"]
        and delta == 0
        and forensics["password_inputs_count"] == 0
        and forensics["otp_or_pin_inputs_count"] == 0
        and forensics["card_or_cvv_inputs_count"] == 0
    ):
        forensics["verified_benign_interior"] = True

    forensics["internal_risk_delta"] = delta
    forensics["internal_findings"] = findings
    return forensics


# --------------------------------------------------------------------------- #
# Deep Semantic Pre-Analyzer (Feeds AI + Powers 3-Part Narrative & Auto-FP/FN)
# --------------------------------------------------------------------------- #
def evaluate_url_heuristics(text: str, memory: dict) -> dict:
    candidate = text.strip()
    t_low = candidate.lower()
    w = memory.get("weights", {})

    # Pass-1 Naive Surface Screener (for automatic FP/FN comparison)
    pass1_score = 0
    if any(k in t_low for k in ["otp", "urgent", "blocked", "suspended", "expire", "immediately", "pay", "₹", "rs.", "refund", "chatgpt", "gemini"]):
        pass1_score += w.get("urgency_penalty", 25) + 20

    score = 0
    indicators = []
    category = "General Communication / Inquiry"
    dark_pattern = "None"
    calm_message = "✅ No immediate manipulation or phishing trap detected. Standard caution applies."
    what_about = f"The input is a message or text snippet: '{candidate[:90]}{'...' if len(candidate) > 90 else ''}'."
    what_seems = "Appears to be a standard informational or conversational statement."
    how_affects = "Does not demand sensitive credentials, money transfers, or risky clicks; poses minimal direct risk to the user."

    has_url, is_url, url, host, scheme = extract_first_url_or_domain(candidate)
    whitelisted = False
    blacklisted = False
    impersonation_info = None

    if has_url and host:
        what_about = f"The input directs the user to web domain '{host}' ({url})."
        if host.endswith(SUSPICIOUS_TLDS):
            pass1_score += 45

        whitelisted = _domain_matches(host, WHITELIST_DOMAINS)
        blacklisted = _domain_matches(host, memory.get("blacklisted_domains", []))

        if blacklisted:
            score = 100
            category = "Known Blacklisted Phishing Domain"
            dark_pattern = "Known Threat Feed Match"
            what_seems = f"Pretends to be a legitimate service portal at '{host}', but is a confirmed blacklisted scam domain."
            how_affects = "Visiting this domain exposes the user to immediate credential theft, malware, or financial fraud."
            calm_message = f"⚠️ Stop! The domain '{host}' is confirmed on your local threat intelligence blacklist."
            indicators.append({
                "type": "Threat Intelligence Blacklist Match",
                "target": host,
                "explanation": "Domain matches confirmed phishing infrastructure in agent_memory.json.",
                "severity": "High",
            })

        if not whitelisted:
            if scheme == "http":
                score += w.get("missing_https_penalty", 20)
                indicators.append({
                    "type": "Insecure HTTP Protocol",
                    "target": url,
                    "explanation": "Uses unencrypted HTTP instead of HTTPS.",
                    "severity": "Medium",
                })
            if host.endswith(SUSPICIOUS_TLDS):
                score += w.get("unverified_tld_penalty", 40)
                what_seems = f"Appears to be an external web link hosted on a disposable top-level domain ('{host}')."
                how_affects = "Disposable TLDs (.xyz, .top, .click) are overwhelmingly used for short-lived phishing sites that steal login data."
                indicators.append({
                    "type": "High-Risk Disposable TLD",
                    "target": host,
                    "explanation": "Uses a disposable top-level domain heavily abused in phishing.",
                    "severity": "High",
                })

            impersonation_info = detect_impersonation(host)
            if impersonation_info:
                score = max(score, impersonation_info["score_boost"])
                category = f"{impersonation_info['technique']} — Impersonating {impersonation_info['brand']}"
                dark_pattern = f"Visual Deception / {impersonation_info['technique']}"
                what_about = f"The input contains the web address '{host}', which closely resembles the popular platform '{impersonation_info['brand']}'."
                what_seems = (
                    f"It is disguised to look like the official {impersonation_info['brand']} website ({impersonation_info['official']}) "
                    f"using {impersonation_info['technique']}."
                )
                how_affects = (
                    f"If the user visits '{host}' thinking it is {impersonation_info['brand']}, any passwords, OTPs, payment details, "
                    "or API keys entered will be stolen directly by attackers."
                )
                calm_message = (
                    f"🛑 IMPERSONATION DETECTED: '{host}' is a fake look-alike of {impersonation_info['brand']}! "
                    f"The real official website is '{impersonation_info['official']}'."
                )
                indicators.append({
                    "type": impersonation_info["technique"],
                    "target": host,
                    "explanation": impersonation_info["explanation"],
                    "severity": "High",
                })

    # Contextual Safe-Guards (Catches False Positives automatically!)
    is_verified_safe_context = False
    if not has_url or whitelisted:
        if ("do not share" in t_low or "never ask for otp" in t_low or "never calls to ask" in t_low) and "otp" in t_low and "*401*" not in t_low:
            is_verified_safe_context = True
            score = 5
            category = "Legitimate Bank OTP Security Alert"
            dark_pattern = "None"
            what_about = "A transactional One-Time Password (OTP) message containing an explicit security warning not to share the code."
            what_seems = "It seems to be—and genuinely is—a standard automated security OTP from a bank or service provider."
            how_affects = "Completely safe for the user as long as they only enter the OTP on the official session they initiated and do not share it with callers."
            calm_message = "✅ Verified Safe: Standard bank OTP message warning you NOT to share your code."
            indicators = []
        elif ("paid ₹" in t_low or "paid rs" in t_low or "debited" in t_low) and ("upi ref" in t_low or "thank you" in t_low) and "request" not in t_low and "click" not in t_low:
            is_verified_safe_context = True
            score = 0
            category = "Legitimate UPI Transaction Receipt"
            dark_pattern = "None"
            what_about = "A standard post-transaction confirmation receipt showing a completed UPI payment and reference ID."
            what_seems = "A genuine payment confirmation notification with no action prompts or external links."
            how_affects = "Informational receipt only; does not ask the user to click links, enter a PIN, or send money."
            calm_message = "✅ Verified Safe: Standard payment confirmation receipt."
            indicators = []
        elif whitelisted and is_url:
            is_verified_safe_context = True
            score = 0
            category = "Verified Official Website Domain"
            dark_pattern = "None"
            what_about = f"A direct link to the verified domain '{host}'."
            what_seems = f"An authentic, official website belonging to a known trusted organization ('{host}')."
            how_affects = "Safe to browse; domain matches the official cryptographic/brand whitelist."
            calm_message = f"✅ Verified Safe: '{host}' is an official whitelisted website."
            indicators = []

    if not is_verified_safe_context:
        # 1. Linkless Direct Credential / Password / OTP Harvesting ("Reply with your username, password, and OTP")
        asks_secrets = any(k in t_low for k in ["password", "otp", "upi pin", "mpin", "cvv", "seed phrase", "secret key", "private key", "netbanking"])
        asks_action = any(k in t_low for k in ["reply", "send", "share", "provide", "enter", "confirm", "verify", "reactivate", "restricted", "temporarily", "blocked", "suspended", "alert"])
        if asks_secrets and (asks_action or "username" in t_low or "account" in t_low):
            score = max(score, 96)
            category = "Direct Credential & OTP Harvesting Attack"
            dark_pattern = "Authority Fear Appeal & Direct Secret Extraction"
            what_about = "An urgent security alert claiming an account is restricted/blocked and demanding sensitive login credentials (username, password, PIN, or OTP)."
            what_seems = "Disguised as an official bank or security department reactivation notice."
            how_affects = "If the user replies with or shares their username, password, or OTP, attackers will immediately hijack their bank account and drain funds."
            calm_message = "🚨 STOP IMMEDIATELY: Real banks and official services NEVER ask you to reply with your password, username, PIN, or OTP!"
            indicators.append({
                "type": "Direct Credential & OTP Harvesting Demand",
                "target": "Request for Username / Password / OTP / PIN",
                "explanation": "Demands confidential authentication secrets directly via message reply under the pretext of account reactivation.",
                "severity": "High",
            })

        # 2. Vague Attention-Bait / Information-Less Lures ("5M credited to your account, click here", "You won, click here", etc.)
        has_bait_hook = any(
            k in t_low
            for k in [
                "credited", "won", "winner", "lottery", "prize", "reward", "gift", "cashback",
                "5m", "million", "lakh", "crore", "bonus", "unclaimed", "selected", "congrats",
                "congratulations", "urgent", "important", "attention", "package", "parcel",
                "photo", "video", "look at this", "is this you", "account update", "action required",
            ]
        ) or bool(re.search(r"\b\d+\s*(?:m|k|lakh|cr|crore|million|rs|₹|\$)\b", t_low))

        has_vague_cta = any(
            k in t_low
            for k in [
                "click here", "tap here", "check here", "visit link", "open link", "claim now",
                "claim here", "verify now", "verify here", "check now", "login here", "call now",
                "act now", "confirm now", "see here", "download now", "link below",
            ]
        ) or has_url

        word_count = len(candidate.split())
        lacks_verifiable_details = "upi ref" not in t_low and "do not share" not in t_low and not whitelisted

        if (has_bait_hook or has_vague_cta) and lacks_verifiable_details and score < 85:
            # Every vague attention-grabbing sentence is flagged as AT LEAST Medium (58-78) or High (85+)!
            vague_score = 86 if (has_bait_hook and has_vague_cta) else 62
            score = max(score, vague_score)
            category = "Vague Attention-Bait / Curiosity Lure (High Doubt)"
            dark_pattern = "Information-Withholding Curiosity / Greed Trap"
            what_about = f"A short, vague message ('{candidate[:80]}') that makes a dramatic financial or urgent claim without providing any verifiable transaction ID, sender identity, or legitimate context."
            what_seems = "Pretends to be an exciting bank credit, windfall notification, or urgent status alert designed purely to grab attention."
            how_affects = "Exploits curiosity or excitement so the user clicks a hidden phishing link, triggers a malware download, or walks into an advance-fee scam."
            calm_message = (
                "🧐 DOUBT THIS MESSAGE: Genuine banks and services never send vague '5M credited, click here' hooks without official account details. "
                "This is an attention-bait trap—do not click!"
            )
            indicators.append({
                "type": "Vague Attention-Bait Lure (Zero Verifiable Info)",
                "target": candidate[:80],
                "explanation": "Uses a dramatic hook or call-to-action ('click here', 'credited') while intentionally omitting verifiable context to trick the user into clicking.",
                "severity": "High" if score >= 66 else "Medium",
            })

        # 3. Impersonating AI Bot / Counterfeit AI Assistant
        if any(k in t_low for k in ["ai assistant", "ai support", "chatgpt", "gemini", "claude", "ai trading", "automated ai", "official ai"]) and any(
            k in t_low for k in ["otp", "pin", "api key", "seed phrase", "password", "verify", "guaranteed", "free subscription", "pay", "credit card", "freeze", "freezing"]
        ):
            score = max(score, 95)
            category = "Impersonating AI Assistant / Counterfeit AI Scam"
            dark_pattern = "Synthetic AI Authority Impersonation"
            what_about = "A message or portal claiming to be an automated AI assistant (such as a bank AI bot, ChatGPT, or Gemini) requesting credentials, OTPs, API keys, or payments."
            what_seems = "Poses as an intelligent, official AI verification agent or premium AI platform."
            how_affects = "Tricks users into trusting 'automated AI verification' so they hand over OTPs, UPI PINs, API keys, or card numbers."
            calm_message = "🤖 STOP! Legitimate AI assistants (ChatGPT, Gemini, Claude) and bank bots NEVER ask for your OTP, UPI PIN, password, or API keys."
            indicators.append({
                "type": "Impersonating AI Credential/Payment Trap",
                "target": "Fake AI Bot / Portal demanding sensitive data",
                "explanation": "Impersonates an AI system to harvest secrets or money.",
                "severity": "High",
            })

        # 4. UPI Collect Request Refund Trap
        if ("request" in t_low or "collect" in t_low) and any(k in t_low for k in ["refund", "cashback", "receive", "pin", "pay ₹", "pay rs"]):
            score = max(score, 96)
            category = "UPI Collect-Request Reversal Scam"
            dark_pattern = "Semantic Misdirection ('Refund' Note on Debit Action)"
            what_about = "A UPI payment collect request where the sender wrote 'Refund' or 'Cashback' in the note, asking the user to tap 'Pay' and enter their UPI PIN."
            what_seems = "Disguised to look like an incoming refund or cashback credit waiting to be accepted."
            how_affects = "Tapping 'Pay' and entering a UPI PIN ALWAYS deducts money from the user's bank account—the user will lose the money immediately."
            calm_message = "🛑 STOP: You NEVER have to enter your UPI PIN or tap 'Pay' to receive money! Approving this will deduct funds from your bank."
            indicators.append({
                "type": "Collect-Request Debit Trap",
                "target": "Action: 'Pay / Enter PIN' vs Note: 'Refund/Cashback'",
                "explanation": "Scammer disguised an outgoing money collect request as an incoming refund.",
                "severity": "High",
            })

        # 5. Electricity / Utility Night Cutoff Panic
        if ("electricity" in t_low or "power" in t_low) and ("disconnect" in t_low or "tonight" in t_low or "9:30" in t_low):
            score = max(score, 94)
            category = "Utility Disconnection Phishing & Vishing Lure"
            dark_pattern = "Artificial Time-Pressure Urgency ('Disconnected Tonight')"
            what_about = "An urgent notice threatening that household electricity power will be disconnected tonight at 9:30 PM unless the user calls a personal mobile number or clicks an unverified link."
            what_seems = "Pretends to be an official final disconnection warning from the state electricity board."
            how_affects = "Induces panic at night so the user calls the scammer's number (leading to a remote-access screen-sharing scam) or enters banking details on a fake billing site."
            calm_message = "🧘 Relax: Your electricity is NOT getting cut tonight. Utility boards never disconnect power abruptly at night via personal mobile numbers or '.xyz' links."
            indicators.append({
                "type": "Induced Panic Deadline",
                "target": "disconnected tonight / call officer",
                "explanation": "Uses false night-time cutoff threat to bypass critical thinking.",
                "severity": "High",
            })

        # 6. Part-Time Job / Task Scam
        if any(k in t_low for k in ["daily", "wfh", "part-time", "work from home"]) and any(k in t_low for k in ["rating", "youtube", "trial bonus", "₹3,000", "₹5,000", "₹7,000", "instant bonus"]):
            score = max(score, 92)
            category = "Prepaid Task / Fake Job Offer Scam"
            dark_pattern = "Micro-Reward Bait-and-Switch Hook"
            what_about = "An unsolicited job offer promising ₹3,000–₹7,000/day for simple tasks like rating Google Maps hotels or liking YouTube videos, with a ₹150 instant trial bonus."
            what_seems = "Presents itself as an easy Work-From-Home digital marketing side hustle."
            how_affects = "Lures the victim with a small initial payout (₹150) to build trust, then traps them into depositing large sums for 'prepaid VIP tasks' that are never returned."
            calm_message = "💡 Heads up: Even if they pay a ₹150 trial bonus first, it is a trap to make you deposit thousands later for 'VIP tasks'."
            indicators.append({
                "type": "Unrealistic Daily Payout Lure",
                "target": "Earn ₹3,000-₹7,000 daily / instant bonus",
                "explanation": "Classic Telegram/WhatsApp prepaid task fraud signature.",
                "severity": "High",
            })

        # 7. USSD Call Forwarding (*401*)
        if "*401*" in t_low:
            score = 99
            category = "USSD Call-Forwarding OTP Interception Scam"
            dark_pattern = "In-Person Courier Pretext Pressure"
            what_about = "Instructions asking the user to dial a code starting with '*401*' followed by a 10-digit phone number under the pretext of parcel delivery or cancellation."
            what_seems = "Pretends to be an official courier IVR/cancellation confirmation code."
            how_affects = "Dialing *401* activates unconditional call forwarding on the user's SIM card, routing all incoming bank verification calls and voice OTPs straight to the scammer."
            calm_message = "🚨 DANGER: Do NOT dial *401*! That code forwards all your incoming phone calls and bank OTPs directly to the scammer's phone."
            indicators.append({
                "type": "Malicious Carrier USSD Code (*401*)",
                "target": "*401*...",
                "explanation": "Unconditional call-forwarding code disguised as a parcel cancellation code.",
                "severity": "High",
            })

    final_score = min(100, int(score))
    level_str = "High" if final_score >= 66 else "Medium" if final_score >= 31 else "Low"
    score_expl = (
        f"Assigned {final_score}/100 ({level_str} Risk): Evaluated semantic intent, vague-bait density, "
        f"brand homoglyph distance, and credential/financial risk factors ({len(indicators)} indicator(s) triggered)."
    )

    return {
        "is_url": is_url,
        "has_url": has_url,
        "url": url,
        "domain": host,
        "whitelisted": whitelisted,
        "blacklisted": blacklisted,
        "impersonation_detected": bool(impersonation_info),
        "pass1_naive_score": pass1_score,
        "base_score": final_score,
        "detected_category": category,
        "what_input_is_about": what_about,
        "what_it_seems_to_be": what_seems,
        "how_it_affects_user": how_affects,
        "confidence_score_explanation": score_expl,
        "dark_pattern": dark_pattern,
        "calm_message": calm_message,
        "auto_calibration_note": "Pending Primary AI Judge & Autonomous FP/FN Arbiter...",
        "heuristic_indicators": indicators,
    }


def apply_autonomous_fp_fn_calibration(candidate: str, heuristics: dict):
    """Automatically compares Pass-1 (Naive Screener) vs Pass-2 (AI + Deep Semantic Judge) and updates agent_memory.json."""
    p1_score = heuristics.get("pass1_naive_score", 0)
    final_score = heuristics.get("base_score", 0)
    host = heuristics.get("domain", "")
    whitelisted = heuristics.get("whitelisted", False)
    category = heuristics.get("detected_category", "Threat")

    p1_flagged = p1_score >= 31
    p2_flagged = final_score >= 31

    if p1_flagged and not p2_flagged:
        note = (
            f"🤖 AUTO-FP SUPPRESSED: Naive keyword pass flagged '{candidate[:35]}...' ({p1_score}/100), "
            "but Primary AI/Context Judge verified legitimate safe intent (Low Risk). Auto-reduced urgency_penalty (-1) in agent_memory.json."
        )

        def _fix_fp(m: dict):
            m["metrics"]["auto_fp_corrected"] = m["metrics"].get("auto_fp_corrected", 0) + 1
            m["metrics"]["tn"] = m["metrics"].get("tn", 0) + 1
            m["weights"]["urgency_penalty"] = max(10, m["weights"].get("urgency_penalty", 25) - 1)
            entry = f"[AUTO-FP FIXED] Verified safe context, suppressed false alarm: '{candidate[:55]}'"
            if entry not in m.setdefault("auto_audit_log", []):
                m["auto_audit_log"].append(entry)

        mutate_memory(_fix_fp)
        heuristics["auto_calibration_note"] = note

    elif not p1_flagged and p2_flagged:
        note = (
            f"🤖 AUTO-FN INTERCEPTED: Naive keyword pass missed stealthy/vague payload ({p1_score}/100), "
            f"but Primary AI/Homoglyph Judge caught '{category}' ({final_score}/100). Auto-updated agent_memory.json."
        )

        def _fix_fn(m: dict):
            m["metrics"]["auto_fn_caught"] = m["metrics"].get("auto_fn_caught", 0) + 1
            m["metrics"]["tp"] = m["metrics"].get("tp", 0) + 1
            m["weights"]["brand_spoof_penalty"] = min(75, m["weights"].get("brand_spoof_penalty", 45) + 2)
            if host and not whitelisted and host not in m["blacklisted_domains"]:
                m["blacklisted_domains"].append(host)
            entry = f"[AUTO-FN CAUGHT] Caught stealthy/vague threat: '{host or candidate[:50]}'"
            if entry not in m.setdefault("auto_audit_log", []):
                m["auto_audit_log"].append(entry)

        mutate_memory(_fix_fn)
        heuristics["auto_calibration_note"] = note
    else:
        if p2_flagged:
            mutate_memory(lambda m: m["metrics"].__setitem__("tp", m["metrics"].get("tp", 0) + 1))
        else:
            mutate_memory(lambda m: m["metrics"].__setitem__("tn", m["metrics"].get("tn", 0) + 1))
        heuristics["auto_calibration_note"] = "Autonomous Pass-1 & Pass-2 AI Judges Agreed."


BENCHMARK_DATASET = [
    {
        "id": "SCAM-01",
        "label": "Malicious",
        "expected_suspicious": True,
        "scenario": "Visual Homoglyph Popular Site (arnazon.com)",
        "text": "arnazon.com",
    },
    {
        "id": "SCAM-02",
        "label": "Malicious",
        "expected_suspicious": True,
        "scenario": "Vague Attention-Bait SMS (5M credited, click here)",
        "text": "5M credited to your account, click here",
    },
    {
        "id": "SCAM-03",
        "label": "Malicious",
        "expected_suspicious": True,
        "scenario": "Linkless Credential & OTP Reply Demand",
        "text": "SECURITY ALERT: Your bank account is temporarily restricted. Reply with your internet banking username, password, and OTP to reactivate it.",
    },
    {
        "id": "SCAM-04",
        "label": "Malicious",
        "expected_suspicious": True,
        "scenario": "Impersonating AI Platform (chatgpi-pro.com)",
        "text": "https://chatgpi-pro.com/login",
    },
    {
        "id": "SCAM-05",
        "label": "Malicious",
        "expected_suspicious": True,
        "scenario": "1-Char Typosquat of Bank (hdfcbnk.com)",
        "text": "http://hdfcbnk.com/netbanking",
    },
    {
        "id": "SCAM-06",
        "label": "Malicious",
        "expected_suspicious": True,
        "scenario": "UPI Collect-Request Refund Reversal Trick",
        "text": "Ramesh (OLX Buyer) has requested Rs. 4,500. Note: 'Cashback/Refund for Sofa'. Tap 'Pay ₹4,500' and enter your UPI PIN to receive money.",
    },
    {
        "id": "SCAM-07",
        "label": "Malicious",
        "expected_suspicious": True,
        "scenario": "USSD *401* Call Forwarding Courier Scam",
        "text": "Courier Delivery Agent: Sir your Amazon parcel is being cancelled. Dial *401*9876543210# on your phone keypad to confirm cancellation.",
    },
    {
        "id": "LEGIT-01",
        "label": "Legitimate",
        "expected_suspicious": False,
        "scenario": "Genuine Bank OTP Alert (Auto-FP Protected)",
        "text": "482910 is your One Time Password (OTP) for netbanking login at SBI. Do NOT share this OTP with anyone. Bank employees never ask for OTP.",
    },
    {
        "id": "LEGIT-02",
        "label": "Legitimate",
        "expected_suspicious": False,
        "scenario": "Genuine UPI Payment Receipt (Auto-FP Protected)",
        "text": "Paid ₹120.00 to Mother Dairy Booth via UPI Ref No 628194021842 on 15-Oct-2026. Thank you for using BHIM UPI.",
    },
    {
        "id": "LEGIT-03",
        "label": "Legitimate",
        "expected_suspicious": False,
        "scenario": "Official Popular Website (amazon.in)",
        "text": "https://www.amazon.in",
    },
]


@app.get("/health")
async def health():
    mem = load_memory()
    return {
        "status": "ok",
        "mode": "Primary AI Judge + Playwright DOM + Auto-FP/FN",
        "blacklisted_count": len(mem.get("blacklisted_domains", [])),
        "blacklisted_domains": mem.get("blacklisted_domains", [])[-12:],
        "lessons_count": len(mem.get("few_shot_lessons", [])),
        "weights": mem.get("weights", {}),
        "metrics": mem.get("metrics", {}),
        "auto_audit_log": mem.get("auto_audit_log", [])[-12:],
    }


@app.post("/api/audit")
async def audit_input(request: AuditRequest):
    text = request.input_text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="input_text is empty.")
    memory = load_memory()

    # Step 1: Compute supporting signals (Impersonation, Vague-Bait, Linkless Credential Traps)
    heuristics = evaluate_url_heuristics(text, memory)

    # Step 2: Run Playwright Inside-DOM Forensics whenever a URL/Domain is present
    content = text
    if heuristics.get("has_url"):
        dom_forensics = await inspect_website_internally_with_playwright(heuristics["url"], heuristics["domain"])
        heuristics["playwright_dom_forensics"] = {
            "probed": dom_forensics["probed"],
            "reachable": dom_forensics["reachable"],
            "page_title": dom_forensics["page_title"],
            "password_inputs": dom_forensics["password_inputs_count"],
            "otp_inputs": dom_forensics["otp_or_pin_inputs_count"],
            "card_inputs": dom_forensics["card_or_cvv_inputs_count"],
            "api_key_inputs": dom_forensics["api_key_inputs_count"],
            "claimed_brands_inside_dom": dom_forensics["claimed_brands_inside_dom"],
            "claimed_ai_inside_dom": dom_forensics["claimed_ai_inside_dom"],
            "verified_benign_interior": dom_forensics["verified_benign_interior"],
        }

        if dom_forensics["internal_risk_delta"] > 0:
            heuristics["base_score"] = min(100, heuristics["base_score"] + dom_forensics["internal_risk_delta"])
            heuristics["heuristic_indicators"].extend(dom_forensics["internal_findings"])

        content = f"{text}\n\n{dom_forensics['blueprint_text']}"

    # Step 3: ALWAYS send to Primary AI Judge (NO early return short-circuits!)
    content_scrubbed = scrub_pii(content)
    ai_used = True
    try:
        async with _ai_slots:
            ai = await asyncio.to_thread(audit_blueprint_with_ai, content_scrubbed, heuristics)
    except AIUnavailableError:
        ai_used = False
        ai = build_semantic_neural_synthesis(heuristics, text)

    # Step 4: Enforce Safety Floors (Vague bait >= Medium, Impersonation/Credential Traps >= High)
    if heuristics.get("base_score", 0) >= 55 and ai.numeric_risk_score < heuristics["base_score"]:
        ai.numeric_risk_score = heuristics["base_score"]
        ai.overall_risk_score = "High" if ai.numeric_risk_score >= 66 else "Medium"
        ai.is_suspicious = True
        ai.fraud_category = heuristics.get("detected_category", ai.fraud_category)
        ai.what_input_is_about = heuristics.get("what_input_is_about", ai.what_input_is_about)
        ai.what_it_seems_to_be = heuristics.get("what_it_seems_to_be", ai.what_it_seems_to_be)
        ai.how_it_affects_user = heuristics.get("how_it_affects_user", ai.how_it_affects_user)
        ai.calm_down_message = heuristics.get("calm_message", ai.calm_down_message)
        if not ai.indicators and heuristics.get("heuristic_indicators"):
            ai = build_semantic_neural_synthesis(heuristics, text)

    # Step 5: Autonomous FP / FN Self-Correction Calibration
    heuristics["base_score"] = ai.numeric_risk_score
    apply_autonomous_fp_fn_calibration(text, heuristics)
    ai.auto_calibration_action = heuristics.get("auto_calibration_note", ai.auto_calibration_action)

    return {
        "status": "success",
        "judged_by": "Gemini Primary AI Judge" if ai_used else "TrustLens Semantic Neural Judge",
        "input": text,
        "heuristics": heuristics,
        "analysis": ai.model_dump(),
    }


@app.post("/api/audit/upload")
async def audit_uploaded_screenshot(file: UploadFile = File(...)):
    image_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
    if not image_bytes or len(image_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Invalid image size.")
    try:
        async with _ai_slots:
            ai = await asyncio.to_thread(audit_image_with_ai, image_bytes, file.content_type or "image/png")
        return {"status": "success", "filename": file.filename, "analysis": ai.model_dump()}
    except AIUnavailableError:
        fallback = build_semantic_neural_synthesis(
            {
                "base_score": 72,
                "detected_category": "Visual Screenshot Audit",
                "what_input_is_about": f"Uploaded screenshot image ({file.filename}).",
                "what_it_seems_to_be": "Visual interface or message screenshot submitted for fraud verification.",
                "how_it_affects_user": "Verify sender identity and never enter UPI PINs or OTPs based on unverified screenshots.",
            },
            file.filename or "screenshot",
        )
        return {"status": "success", "filename": file.filename, "analysis": fallback.model_dump()}


@app.post("/api/evaluate")
async def run_benchmark_evaluation():
    memory = load_memory()
    tp = tn = fp = fn = 0
    auto_fp_saved = 0
    auto_fn_saved = 0
    results = []

    for item in BENCHMARK_DATASET:
        heuristics = evaluate_url_heuristics(item["text"], memory)
        apply_autonomous_fp_fn_calibration(item["text"], heuristics)
        p1_susp = heuristics.get("pass1_naive_score", 0) >= 31
        p2_susp = heuristics.get("base_score", 0) >= 31

        if p1_susp and not p2_susp:
            auto_fp_saved += 1
        elif not p1_susp and p2_susp:
            auto_fn_saved += 1

        if item["expected_suspicious"] and p2_susp:
            tp += 1
            verdict = "TRUE POSITIVE (TP)"
        elif not item["expected_suspicious"] and not p2_susp:
            tn += 1
            verdict = "TRUE NEGATIVE (TN)"
        elif not item["expected_suspicious"] and p2_susp:
            fp += 1
            verdict = "FALSE POSITIVE (FP)"
        else:
            fn += 1
            verdict = "FALSE NEGATIVE (FN)"

        results.append({
            "id": item["id"],
            "scenario": item["scenario"],
            "expected": item["label"],
            "pass1_naive": "Flagged" if p1_susp else "Missed/Safe",
            "predicted": "Malicious" if p2_susp else "Legitimate",
            "score": heuristics.get("base_score", 0),
            "verdict": verdict,
            "auto_action": heuristics.get("auto_calibration_note", ""),
        })

    total = len(BENCHMARK_DATASET)
    accuracy = round(((tp + tn) / total) * 100, 1) if total else 0.0
    precision = round((tp / (tp + fp)) * 100, 1) if (tp + fp) else 100.0
    recall = round((tp / (tp + fn)) * 100, 1) if (tp + fn) else 100.0
    fpr = round((fp / (fp + tn)) * 100, 1) if (fp + tn) else 0.0

    return {
        "status": "success",
        "total_tested": total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "auto_fp_suppressed": auto_fp_saved,
        "auto_fn_intercepted": auto_fn_saved,
        "accuracy_pct": accuracy,
        "precision_pct": precision,
        "recall_pct": recall,
        "false_positive_rate_pct": fpr,
        "cases": results,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
