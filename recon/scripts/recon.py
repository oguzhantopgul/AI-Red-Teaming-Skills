#!/usr/bin/env python3
"""recon.py — one-shot reconnaissance toolkit for the `recon` skill.

Run the whole sweep against a target with a single command:

    python3 recon.py example.com
    python3 recon.py acme.example.com --ai-endpoint https://acme.example.com/chat

That runs DNS, certificate-transparency subdomains, RDAP/WHOIS, HTTP
fingerprint, TLS inspection, a TCP port/service scan, and an API/endpoint sweep
(curated AI/LLM wordlist) — plus a first AI-endpoint probe when one is given —
and prints ONE JSON evidence bundle to stdout. Each scan is also available as its
own subcommand (dns, subdomains, rdap, http, tls, ports, endpoints, ai-probe) for
targeted follow-ups.

Only run this against targets you are authorized to test. As a guardrail the
tool refuses cloud-metadata / reserved IP ranges and never follows redirects.

stdlib-only: it uses httpx / dnspython / nmap automatically when installed and
falls back to urllib / dig / socket / a pure-Python connect scan otherwise, so
it runs anywhere Python does.

Adapted from oguzhantopgul/kirmizi-recon (Apache-2.0).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlsplit

TIMEOUT = 15.0
UA = "recon-skill/2.0 (authorized security testing)"

try:
    import httpx  # type: ignore
    HAVE_HTTPX = True
except Exception:
    HAVE_HTTPX = False

try:
    import dns.resolver  # type: ignore
    HAVE_DNS = True
except Exception:
    HAVE_DNS = False


# ---------------------------------------------------------------------------
# Minimal HTTP client — uniform surface over httpx or urllib. No redirects.
# ---------------------------------------------------------------------------
class Resp:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self._pairs = [(k.lower(), v) for k, v in headers]
        self.content = body

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def header(self, name: str, default: str = "") -> str:
        name = name.lower()
        return next((v for k, v in self._pairs if k == name), default)

    def header_list(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self._pairs if k == name]

    def json(self) -> Any:
        return json.loads(self.content.decode("utf-8", "replace"))


def http_request(method: str, url: str, *, headers=None, body=None,
                 timeout: float = TIMEOUT, verify: bool = True) -> Resp:
    """One HTTP(S) request; redirects are NOT followed. Raises on transport error."""
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    if HAVE_HTTPX:
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=verify,
                          headers=hdrs) as client:
            r = client.request(method, url, content=body)
            return Resp(r.status_code, list(r.headers.multi_items()), r.content)

    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
            return None  # surface the 3xx instead of following it

    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect,
                                         urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=hdrs)
    try:
        r = opener.open(req, timeout=timeout)
        return Resp(r.status, list(r.headers.items()), r.read())
    except urllib.error.HTTPError as e:
        return Resp(e.code, list(e.headers.items()) if e.headers else [], e.read() or b"")


# ---------------------------------------------------------------------------
# Minimal safety guardrail: refuse cloud-metadata / reserved IPs (SSRF), and
# never follow redirects (enforced in http_request). Private/loopback are
# allowed so you can recon local dev targets.
# ---------------------------------------------------------------------------
def host_from(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}", scheme="https")
    return (parsed.hostname or "").lower().rstrip(".")


def resolve_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except OSError:
            return ""


def blocked_reason(host: str) -> str:
    """Return a refusal reason if the host resolves to a blocked range, else ''."""
    ip = resolve_ip(host)
    if not ip:
        return f"could not resolve '{host}'"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return (f"'{host}' resolves to blocked IP {ip} (link-local/metadata/reserved) "
                "— refused as an SSRF guardrail")
    return ""


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------
def dns_lookup(domain: str) -> dict[str, Any]:
    """A/AAAA/MX/TXT/NS/CNAME for a domain."""
    records: dict[str, Any] = {"domain": domain}
    types = ("A", "AAAA", "MX", "TXT", "NS", "CNAME")
    if HAVE_DNS:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = TIMEOUT
        for rtype in types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = sorted(a.to_text().strip('"') for a in answers)
            except Exception as exc:
                records[rtype] = f"(none: {type(exc).__name__})"
        records["_resolver"] = "dnspython"
        return records
    if shutil.which("dig"):
        for rtype in types:
            try:
                out = subprocess.run(["dig", "+short", domain, rtype],
                                     capture_output=True, timeout=TIMEOUT, text=True)
                vals = [ln.strip().strip('"') for ln in out.stdout.splitlines() if ln.strip()]
                records[rtype] = sorted(vals) if vals else "(none)"
            except Exception as exc:
                records[rtype] = f"(error: {type(exc).__name__})"
        records["_resolver"] = "dig"
        return records
    try:
        infos = socket.getaddrinfo(domain, None)
        records["A"] = sorted({i[4][0] for i in infos if ":" not in i[4][0]}) or "(none)"
        records["AAAA"] = sorted({i[4][0] for i in infos if ":" in i[4][0]}) or "(none)"
    except OSError as exc:
        records["error"] = f"{type(exc).__name__}: {exc}"
    records["_resolver"] = "socket (A/AAAA only — install dnspython for more)"
    return records


def ct_subdomains(domain: str, limit: int = 200) -> dict[str, Any]:
    """Subdomains from crt.sh certificate-transparency logs."""
    try:
        r = http_request("GET", f"https://crt.sh/?q=%25.{domain}&output=json")
        if r.status != 200:
            return {"domain": domain, "error": f"crt.sh returned {r.status}"}
        rows = r.json()
    except Exception as exc:
        return {"domain": domain, "error": f"{type(exc).__name__}: {exc}"}
    names: set[str] = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                names.add(name)
    ordered = sorted(names)
    return {"domain": domain, "count": len(ordered),
            "subdomains": ordered[:limit], "truncated": len(ordered) > limit}


def rdap_lookup(domain: str) -> dict[str, Any]:
    """RDAP (modern WHOIS) via rdap.org."""
    try:
        r = http_request("GET", f"https://rdap.org/domain/{domain}")
        if 300 <= r.status < 400 and r.header("location"):
            r = http_request("GET", r.header("location"))
        if r.status != 200:
            return {"domain": domain, "error": f"rdap returned {r.status}"}
        data = r.json()
    except Exception as exc:
        return {"domain": domain, "error": f"{type(exc).__name__}: {exc}"}
    registrar = ""
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in entity.get("vcardArray", [[], []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    return {"domain": domain, "handle": data.get("handle", ""), "registrar": registrar,
            "status": data.get("status", []),
            "events": {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])},
            "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])]}


_SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                     "x-frame-options", "x-content-type-options", "referrer-policy",
                     "permissions-policy"]
_FINGERPRINT_HEADERS = ["server", "x-powered-by", "via", "x-aspnet-version"]


def _origin(url: str) -> str:
    p = urlsplit(url if "://" in url else "https://" + url)
    return f"{p.scheme}://{p.netloc}"


def http_fingerprint(url: str) -> dict[str, Any]:
    """status, banners, security headers, cookies, title, robots.txt. No redirects."""
    if "://" not in url:
        url = "https://" + url
    reason = blocked_reason(host_from(url))
    if reason:
        return {"url": url, "skipped": True, "reason": reason}
    result: dict[str, Any] = {"url": url}
    try:
        r = http_request("GET", url)
        result["status"] = r.status
        result["location"] = r.header("location")
        result["fingerprint_headers"] = {h: r.header(h) for h in _FINGERPRINT_HEADERS if r.header(h)}
        result["security_headers_present"] = {h: bool(r.header(h)) for h in _SECURITY_HEADERS}
        result["set_cookie_names"] = [c.split("=", 1)[0].strip() for c in r.header_list("set-cookie")]
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:20000], re.I | re.S)
        result["title"] = m.group(1).strip() if m else ""
        try:
            robots = http_request("GET", _origin(url) + "/robots.txt")
            result["robots_txt"] = robots.text[:2000] if robots.status == 200 else f"(status {robots.status})"
        except Exception as exc:
            result["robots_txt"] = f"(error: {type(exc).__name__})"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _flatten_name(rdns: Any) -> str:
    if not rdns:
        return ""
    return ", ".join(f"{k}={v}" for rdn in rdns for (k, v) in rdn)


def tls_inspect(host: str, port: int = 443) -> dict[str, Any]:
    """TLS certificate (subject/issuer/SANs/validity) + protocol/cipher."""
    if "://" in host:
        host = urlparse(host).hostname or host
    reason = blocked_reason(host)
    if reason:
        return {"host": host, "skipped": True, "reason": reason}
    result: dict[str, Any] = {"host": host, "port": port}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                cipher = tls.cipher()
                result.update(protocol=tls.version(), cipher=cipher[0] if cipher else "",
                              valid=True, subject=_flatten_name(cert.get("subject")),
                              issuer=_flatten_name(cert.get("issuer")),
                              not_before=cert.get("notBefore", ""), not_after=cert.get("notAfter", ""),
                              subject_alt_names=[v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"])
    except ssl.SSLCertVerificationError as exc:
        result["valid"] = False
        result["verify_error"] = str(exc)
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as tls:
                    cipher = tls.cipher()
                    result["protocol"] = tls.version()
                    result["cipher"] = cipher[0] if cipher else ""
        except Exception as exc2:
            result["error"] = f"{type(exc2).__name__}: {exc2}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


# -- port scan --------------------------------------------------------------
TOP_100_PORTS = [7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 161, 179, 199, 389, 427, 443, 444, 445, 465, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1434, 1521, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 5985, 6000, 6001, 6379, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 10000,
    27017, 32768]
WEB_PORTS = [80, 443, 3000, 4443, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090]
_PORT_SPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
_SERVICE_HINTS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 587: "smtp", 993: "imaps", 995: "pop3s",
    1433: "ms-sql", 1521: "oracle", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb"}
_HTTP_PORTS = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090}


def _port_list(spec: str) -> list[int]:
    spec = (spec or "top-100").strip().lower()
    if spec in ("", "top-100", "top100", "top-1000", "top1000"):
        return list(TOP_100_PORTS)
    if spec == "web":
        return list(WEB_PORTS)
    if not _PORT_SPEC_RE.match(spec):
        raise ValueError(f"invalid ports '{spec}'. Use top-100, web, '22,80,443', or '1-1024'.")
    ports: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted({p for p in ports if 0 < p <= 65535})[:2048]


def port_scan(host: str, ports: str = "top-100", service: bool = True) -> dict[str, Any]:
    """Open TCP ports + services. nmap -sV when available; connect-scan otherwise."""
    reason = blocked_reason(host_from(host))
    if reason:
        return {"target": host, "skipped": True, "reason": reason}
    ip = resolve_ip(host_from(host))
    if not ip:
        return {"target": host, "error": "could not resolve"}
    if shutil.which("nmap"):
        return _run_nmap(ip, ports, service)
    try:
        plist = _port_list(ports)
    except ValueError as exc:
        return {"target": ip, "error": str(exc)}
    open_ports = _connect_scan(ip, plist, service)
    return {"target": ip, "engine": "python-fallback", "degraded": True,
            "note": "nmap not installed: pure-Python connect scan; no version detection.",
            "open_ports": open_ports, "open_count": len(open_ports)}


def _run_nmap(ip: str, ports: str, service: bool) -> dict[str, Any]:
    argv = ["nmap", "-Pn", "-sT", "-T3", "-oX", "-", "--host-timeout", "180s"]
    if service:
        argv.append("-sV")
    spec = (ports or "top-100").strip().lower()
    if spec in ("top-100", "top100", ""):
        argv += ["--top-ports", "100"]
    elif spec in ("top-1000", "top1000"):
        argv += ["--top-ports", "1000"]
    elif spec == "web":
        argv += ["-p", ",".join(str(p) for p in WEB_PORTS)]
    elif _PORT_SPEC_RE.match(spec):
        argv += ["-p", spec]
    else:
        return {"target": ip, "error": f"invalid ports '{ports}'"}
    argv.append(ip)
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=220)
    except subprocess.TimeoutExpired:
        return {"target": ip, "engine": "nmap", "error": "nmap timed out"}
    except OSError as exc:
        return {"target": ip, "engine": "nmap", "error": f"nmap failed: {exc}"}
    try:
        open_ports = _parse_nmap_xml(proc.stdout)
    except ET.ParseError:
        return {"target": ip, "engine": "nmap", "error": "could not parse nmap output"}
    return {"target": ip, "engine": "nmap", "degraded": False,
            "open_ports": open_ports, "open_count": len(open_ports)}


def _parse_nmap_xml(data: bytes) -> list[dict[str, Any]]:
    if not data.strip():
        return []
    out: list[dict[str, Any]] = []
    for host in ET.fromstring(data).findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            out.append({"port": int(port.get("portid")), "protocol": port.get("protocol", "tcp"),
                        "state": "open", "service": svc.get("name", "") if svc is not None else "",
                        "product": svc.get("product", "") if svc is not None else "",
                        "version": svc.get("version", "") if svc is not None else ""})
    return sorted(out, key=lambda d: d["port"])


def _connect_scan(ip: str, ports: list[int], service: bool, timeout: float = 1.0):
    def probe(port: int):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                banner = ""
                if service:
                    try:
                        sock.settimeout(timeout)
                        if port in _HTTP_PORTS:
                            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(256).decode("utf-8", "replace").strip()[:200]
                    except OSError:
                        pass
        except OSError:
            return None
        return {"port": port, "protocol": "tcp", "state": "open",
                "service": _SERVICE_HINTS.get(port, ""), "banner": banner}
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        results = [r for r in ex.map(probe, ports) if r is not None]
    return sorted(results, key=lambda d: d["port"])


# -- endpoint scan ----------------------------------------------------------
def default_wordlist() -> list[str]:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_endpoints.txt")
    if os.path.exists(path):
        return load_wordlist(path)
    return ["/", "/api", "/api/v1", "/openapi.json", "/swagger.json", "/graphql",
            "/actuator", "/actuator/env", "/.well-known/openid-configuration",
            "/v1/models", "/v1/chat/completions", "/.env", "/.git/config"]


def load_wordlist(path: str) -> list[str]:
    seen, out = set(), []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = line if line.startswith("/") else "/" + line
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def endpoint_scan(base_url: str, endpoints: Optional[list[str]] = None, *,
                  authorization: str = "", workers: int = 12) -> dict[str, Any]:
    """Probe an API/app wordlist against a base URL; group responses. No redirects.
    Every request pinned to the authorized origin (off-origin paths are skipped)."""
    if "://" not in base_url:
        base_url = "https://" + base_url
    reason = blocked_reason(host_from(base_url))
    if reason:
        return {"base_url": base_url, "skipped": True, "reason": reason}
    base = base_url.rstrip("/") + "/"
    base_origin = _origin(base)
    paths = (endpoints or default_wordlist())[:2000]
    headers = {"Accept": "application/json, text/plain, */*"}
    if authorization:
        headers["Authorization"] = authorization

    def probe(path: str) -> dict[str, Any]:
        url = urljoin(base, path.lstrip("/"))
        if _origin(url) != base_origin:
            return {"path": path, "status": "OFFHOST", "length": 0}
        try:
            r = http_request("GET", url, headers=headers, timeout=8.0)
            return {"path": path, "status": r.status, "length": len(r.content),
                    "server": r.header("server"), "location": r.header("location")}
        except Exception as exc:
            return {"path": path, "status": "ERROR", "length": 0, "error": str(exc)[:120]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, 20))) as ex:
        results = list(ex.map(probe, paths))
    return _group_endpoints(base, len(paths), results)


def _group_endpoints(base: str, probed: int, results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"2xx": 0, "3xx": 0, "401": 0, "403": 0, "404": 0, "405": 0,
              "5xx": 0, "other": 0, "error": 0, "offhost_skipped": 0}
    interesting: list[dict[str, Any]] = []
    for r in results:
        s = r["status"]
        if s == "OFFHOST":
            counts["offhost_skipped"] += 1
            continue
        if s == "ERROR":
            counts["error"] += 1
            continue
        if 200 <= s < 300: counts["2xx"] += 1
        elif 300 <= s < 400: counts["3xx"] += 1
        elif s == 401: counts["401"] += 1
        elif s == 403: counts["403"] += 1
        elif s == 404:
            counts["404"] += 1
            continue
        elif s == 405: counts["405"] += 1
        elif 500 <= s < 600: counts["5xx"] += 1
        else: counts["other"] += 1
        interesting.append(r)
    interesting.sort(key=lambda d: (str(d["status"]), d["path"]))
    return {"base_url": base, "probed": probed, "counts": counts,
            "interesting": interesting[:400], "interesting_truncated": len(interesting) > 400,
            "note": "Redirects not followed. 'interesting' = every non-404, non-error response. "
                    "401/403 usually mean the endpoint exists but is protected."}


# -- ai probe ---------------------------------------------------------------
def _dig_path(obj: Any, path: str) -> Any:
    cur = obj
    for seg in path.split("."):
        if seg == "":
            continue
        if isinstance(cur, list):
            try:
                cur = cur[int(seg)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(seg)
        else:
            return None
        if cur is None:
            return None
    return cur


def ai_probe(url: str, prompt: str, *, method: str = "POST", headers=None,
             template: str = '{"messages": [{"role": "user", "content": {prompt}}]}',
             response_path: str = "choices.0.message.content") -> dict[str, Any]:
    """Send ONE probe prompt to a target AI endpoint; return raw + extracted reply.
    Generic HTTP POST so it talks to any provider."""
    result: dict[str, Any] = {"endpoint": url, "prompt": prompt}
    reason = blocked_reason(host_from(url))
    if reason:
        result["skipped"] = True
        result["reason"] = reason
        return result
    try:
        body = json.loads(template.replace("{prompt}", json.dumps(prompt)))
    except json.JSONDecodeError as exc:
        result["error"] = f"template did not parse as JSON: {exc}"
        return result
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    try:
        r = http_request(method, url, headers=hdrs, body=json.dumps(body).encode(), timeout=30.0)
        result["status"] = r.status
        if 300 <= r.status < 400:
            result["redirect_location"] = r.header("location")
        result["raw_response"] = r.text[:4000]
        result["truncated"] = len(r.content) > 4000
        try:
            reply = _dig_path(r.json(), response_path)
            result["reply"] = reply if reply is not None else "(response_path not found)"
        except json.JSONDecodeError:
            result["reply"] = "(non-JSON response; see raw_response)"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


# ---------------------------------------------------------------------------
# The one-shot sweep
# ---------------------------------------------------------------------------
def run_all(targets: list[str], *, ai_endpoints=None, ports="top-100",
            wordlist=None, auth="", ai_headers=None,
            ai_template='{"messages": [{"role": "user", "content": {prompt}}]}',
            ai_response_path="choices.0.message.content") -> dict[str, Any]:
    """Full sweep across one or more domains/hosts + optional AI endpoints."""
    words = load_wordlist(wordlist) if wordlist else default_wordlist()
    ev: dict[str, Any] = {"targets": targets, "ai_endpoints": ai_endpoints or [],
                          "dns": {}, "subdomains": {}, "rdap": {}, "http": {}, "tls": {},
                          "ports": {}, "endpoints": {}, "ai": {}}
    for t in targets:
        host = host_from(t) or t
        url = t if "://" in t else "https://" + t  # keep any :port
        ev["dns"][host] = dns_lookup(host)
        ev["subdomains"][host] = ct_subdomains(host)
        ev["rdap"][host] = rdap_lookup(host)
        ev["http"][host] = http_fingerprint(url)
        ev["tls"][host] = tls_inspect(host)
        ev["ports"][host] = port_scan(host, ports)
        ev["endpoints"][host] = endpoint_scan(url, words, authorization=auth)
    for url in (ai_endpoints or []):
        ev["ai"][url] = ai_probe(url, "In one sentence, what model are you and who created you?",
                                 headers=ai_headers, template=ai_template,
                                 response_path=ai_response_path)
    return ev


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _emit(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _parse_headers(items) -> dict[str, str]:
    out: dict[str, str] = {}
    for it in items or []:
        if ":" in it:
            k, v = it.split(":", 1)
            out[k.strip()] = v.strip()
    return out


_SUBCOMMANDS = {"all", "dns", "subdomains", "rdap", "http", "tls", "ports", "endpoints", "ai-probe"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recon.py",
        description="One-shot recon toolkit. `recon.py <target>` runs the full sweep.")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("all", help="Full sweep (default): DNS+subdomains+RDAP+HTTP+TLS+ports+endpoints[+AI].")
    sp.add_argument("targets", nargs="+")
    sp.add_argument("--ai-endpoint", action="append", default=[], help="AI endpoint URL to probe (repeatable).")
    sp.add_argument("--ports", default="top-100", help="top-100|top-1000|web|'22,80,443'|'1-1024'.")
    sp.add_argument("--wordlist", help="Custom endpoint wordlist (default: bundled api_endpoints.txt).")
    sp.add_argument("--auth", default="", help="Authorization header for endpoint scan, e.g. 'Bearer <tok>'.")
    sp.add_argument("--ai-header", action="append", default=[], help="Header for AI probe 'K: V' (repeatable).")
    sp.add_argument("--ai-template", default='{"messages": [{"role": "user", "content": {prompt}}]}')
    sp.add_argument("--ai-response-path", default="choices.0.message.content")

    for name, help_ in [("dns", "Resolve DNS records."), ("subdomains", "Subdomains from crt.sh."),
                        ("rdap", "RDAP/WHOIS registration data.")]:
        s = sub.add_parser(name, help=help_)
        s.add_argument("domain")

    s = sub.add_parser("http", help="HTTP fingerprint (headers/title/robots)."); s.add_argument("url")
    s = sub.add_parser("tls", help="Inspect the TLS certificate."); s.add_argument("host"); s.add_argument("--port", type=int, default=443)
    s = sub.add_parser("ports", help="Port/service scan."); s.add_argument("target"); s.add_argument("--ports", default="top-100"); s.add_argument("--no-service", action="store_true")
    s = sub.add_parser("endpoints", help="Brute-force API/app endpoints."); s.add_argument("base_url"); s.add_argument("--wordlist"); s.add_argument("--auth", default="")

    s = sub.add_parser("ai-probe", help="Send one probe prompt to a target AI endpoint.")
    s.add_argument("url"); s.add_argument("--prompt", required=True); s.add_argument("--method", default="POST")
    s.add_argument("--header", action="append", default=[])
    s.add_argument("--template", default='{"messages": [{"role": "user", "content": {prompt}}]}')
    s.add_argument("--response-path", default="choices.0.message.content")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Ergonomics: `recon.py example.com` == `recon.py all example.com`.
    if argv and argv[0] not in _SUBCOMMANDS and not argv[0].startswith("-"):
        argv = ["all"] + argv
    args = build_parser().parse_args(argv)
    if not args.cmd:
        build_parser().print_help()
        return 2

    if args.cmd == "all":
        _emit(run_all(args.targets, ai_endpoints=args.ai_endpoint, ports=args.ports,
                      wordlist=args.wordlist, auth=args.auth, ai_headers=_parse_headers(args.ai_header),
                      ai_template=args.ai_template, ai_response_path=args.ai_response_path))
    elif args.cmd == "dns":
        _emit(dns_lookup(args.domain))
    elif args.cmd == "subdomains":
        _emit(ct_subdomains(args.domain))
    elif args.cmd == "rdap":
        _emit(rdap_lookup(args.domain))
    elif args.cmd == "http":
        _emit(http_fingerprint(args.url))
    elif args.cmd == "tls":
        _emit(tls_inspect(args.host, args.port))
    elif args.cmd == "ports":
        _emit(port_scan(args.target, args.ports, not args.no_service))
    elif args.cmd == "endpoints":
        words = load_wordlist(args.wordlist) if args.wordlist else None
        _emit(endpoint_scan(args.base_url, words, authorization=args.auth))
    elif args.cmd == "ai-probe":
        _emit(ai_probe(args.url, args.prompt, method=args.method,
                       headers=_parse_headers(args.header),
                       template=args.template, response_path=args.response_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
