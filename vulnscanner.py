#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# CyberShield-SecureScan - AI-Powered Vulnerability Scanner

import os
import sys
import argparse
import logging
import time
import json
import requests
import ipaddress
import re
import subprocess
import shutil
import shlex
from html import escape
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

from dotenv import load_dotenv
from jinja2 import Template

# ============================================================
# TCI - Target Complexity Index
# ============================================================
try:
    from tci import get_tci_plan
    TCI_AVAILABLE = True
except ImportError:
    TCI_AVAILABLE = False

# ============================================================
# History Database
# ============================================================
try:
    from history_db import store_scan_result, detect_trends
    HISTORY_AVAILABLE = True
except ImportError:
    HISTORY_AVAILABLE = False

# ============================================================
# Environment
# ============================================================
_pre_parser = argparse.ArgumentParser(add_help=False)
_pre_parser.add_argument("--env-file", default=".env")
_pre_args, _ = _pre_parser.parse_known_args()
load_dotenv(_pre_args.env_file)

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# ============================================================
# Configs
# ============================================================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")

REPLIT_API_KEY = os.getenv("REPLIT_API_KEY")
REPLIT_API_URL = os.getenv("REPLIT_API_URL", "https://chat.replit.com/v1/chat/completions")
REPLIT_MODEL = os.getenv("REPLIT_MODEL", "gpt-4o-mini")

ANYTHINGLLM_API_KEY = os.getenv("ANYTHINGLLM_API_KEY")
ANYTHINGLLM_API_URL = os.getenv("ANYTHINGLLM_API_URL")
ANYTHINGLLM_WORKSPACE = os.getenv("ANYTHINGLLM_WORKSPACE", "default")
ANYTHINGLLM_MODEL = os.getenv("ANYTHINGLLM_MODEL")

OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

TEMPERATURE = 0.4
TOKEN_LIMIT = 4096

HTTP_SESSION = requests.Session()
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

retry = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
)
adapter = HTTPAdapter(max_retries=retry)
HTTP_SESSION.mount("https://", adapter)
HTTP_SESSION.mount("http://", adapter)

# ============================================================
# Scan Profiles
# ============================================================
LEGACY_DEFAULT_NMAP_ARGS = "-Pn -sV -T4 -F --host-timeout 5m -vvv"
SCAN_PROFILES: Dict[int, str] = {
    1: LEGACY_DEFAULT_NMAP_ARGS,
    2: "-Pn -p- -sC -sV -T4 --host-timeout 10m -vvv",
    3: "-Pn -sT -sU -T4 --top-ports 1000 --defeat-rst-ratelimit --host-timeout 15m -vvv",
    4: "-Pn -sV -T5 -F --host-timeout 3m -vvv",
}

# ============================================================
# Ethics Banner
# ============================================================
def print_ethical_warning():
    print("\n" + "=" * 80)
    print("WARNING: Use this script ONLY on systems you own or have explicit permission to test.")
    print("Unauthorized scanning is illegal and unethical.")
    print("=" * 80 + "\n")

# ============================================================
# Utilities
# ============================================================
def mask_api_key(key: Optional[str]) -> str:
    if not key or len(key) < 8:
        return "[NOT SET]"
    return key[:4] + "..." + key[-4:]

def sanitize_target(target: str) -> str:
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    target = target.strip().strip("/")
    target = re.sub(r":\d+$", "", target)
    return target

def is_safe_target(target: str) -> bool:
    if re.search(r"[;&|`$<>]", target):
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"[a-zA-Z0-9.-]+", target):
        return True
    return False

def ensure_nmap_available(nmap_path: Optional[str]) -> str:
    if nmap_path:
        if shutil.which(nmap_path) is None and not os.path.exists(nmap_path):
            raise FileNotFoundError(f"nmap not found at '{nmap_path}'")
        return nmap_path
    resolved = shutil.which("nmap")
    if not resolved:
        raise FileNotFoundError("nmap binary not found in PATH. Install nmap first.")
    return resolved

def validate_api_keys(provider: str) -> None:
    p = (provider or "openai").strip().lower()
    key_present = True
    if p == "openai":
        key_present = bool(OPENAI_API_KEY)
    elif p == "gemini":
        key_present = bool(GEMINI_API_KEY)
    elif p in ("anthropic", "claude"):
        key_present = bool(ANTHROPIC_API_KEY)
    elif p == "replit":
        key_present = bool(REPLIT_API_KEY)
    elif p in ("anythingllm", "anything"):
        key_present = bool(ANYTHINGLLM_API_KEY and ANYTHINGLLM_API_URL)
    elif p == "ollama":
        key_present = True
    elif p == "groq":
        key_present = bool(GROQ_API_KEY)
    elif p == "deepseek":
        key_present = bool(DEEPSEEK_API_KEY)
    if not key_present:
        logging.error("Required API key for provider '%s' is not set.", provider)
        sys.exit(1)
    logging.debug("Groq API Key: %s", mask_api_key(GROQ_API_KEY))
    logging.debug("DeepSeek API Key: %s", mask_api_key(DEEPSEEK_API_KEY))

# ============================================================
# Nmap Scanning
# ============================================================
def run_nmap_scan(nmap_bin: str, target: str, nmap_args: str) -> Dict[str, Any]:
    cmd = [nmap_bin] + shlex.split(nmap_args) + ["-oX", "-", target]
    logging.debug("Executing: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=900, check=False)
    except Exception:
        logging.exception("Failed to execute nmap.")
        return {}
    if proc.returncode != 0:
        logging.error("nmap exited with code %s", proc.returncode)
    xml_text = proc.stdout.encode("utf-8", "ignore").decode("utf-8", "ignore").strip()
    if not xml_text.startswith("<?xml") and "<nmaprun" not in xml_text:
        logging.error("nmap output was not valid XML.")
        return {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logging.exception("Failed to parse nmap XML.")
        return {}
    parsed = parse_nmap_xml(root)
    if not parsed.get("hosts"):
        logging.error("Parsed scan contains no hosts.")
        return {}
    return parsed

def parse_nmap_xml(root: ET.Element) -> Dict[str, Any]:
    hosts: List[Dict[str, Any]] = []
    for h in root.findall("host"):
        host_entry = {"status": None, "address": None, "hostnames": [], "ports": [], "os": [], "scripts": []}
        status_el = h.find("status")
        if status_el is not None:
            host_entry["status"] = status_el.attrib.get("state")
        addr_el = h.find("address")
        if addr_el is not None:
            host_entry["address"] = addr_el.attrib.get("addr")
        for hn in h.findall("./hostnames/hostname"):
            name = hn.attrib.get("name")
            if name:
                host_entry["hostnames"].append(name)
        for p in h.findall("./ports/port"):
            protocol = p.attrib.get("protocol")
            portid = int(p.attrib.get("portid", "0"))
            state_el = p.find("state")
            state = state_el.attrib.get("state") if state_el is not None else None
            svc_el = p.find("service")
            service = {}
            if svc_el is not None:
                for k in ("name", "product", "version", "extrainfo"):
                    if svc_el.attrib.get(k):
                        service[k] = svc_el.attrib[k]
            scripts = []
            for s in p.findall("script"):
                scripts.append({"id": s.attrib.get("id"), "output": s.attrib.get("output", "")})
            host_entry["ports"].append({
                "protocol": protocol, "portid": portid, "state": state,
                "service": service, "scripts": scripts
            })
        for s in h.findall("hostscript/script"):
            host_entry["scripts"].append({"id": s.attrib.get("id"), "output": s.attrib.get("output", "")})
        hosts.append(host_entry)
    return {"hosts": hosts}

def extract_open_ports(scan: Dict[str, Any]) -> str:
    parts = []
    for host in scan.get("hosts", []):
        label = (host.get("hostnames") or [host.get("address")])[0]
        for p in host.get("ports", []):
            if p.get("state") == "open":
                proto = (p.get("protocol") or "").upper()
                pid = p.get("portid")
                svc = p.get("service", {}).get("name", "unknown")
                ver = p.get("service", {}).get("version", "")
                suffix = f" ({ver})" if ver else ""
                parts.append(f"{label} {proto} {pid}/{svc}{suffix}")
    return ", ".join(parts) if parts else "(no open ports detected)"

# ============================================================
# AI PROMPT
# ============================================================
def build_ai_prompt(scan: Dict[str, Any], open_ports: str, target: str,
                    *, _scan_json: Optional[str] = None, tci_result: Optional[Dict] = None) -> str:
    scan_json = (_scan_json if _scan_json is not None else json.dumps(scan, indent=2)).replace("```", "'''")
    tci_section = ""
    if tci_result:
        tci_section = f"""
Target Complexity Analysis:
- TCI Score: {tci_result.get('tci_score', 0)}/100
- Severity: {tci_result.get('severity', 'unknown').upper()}
"""
    prompt = f"""
You are a senior penetration tester and vulnerability analyst.

Target: {target}

Nmap scan results (JSON):
{scan_json}

Open ports summary:
{open_ports}
{tci_section}
Tasks:
- Identify vulnerabilities and exposures
- Map to OWASP, CWE, CAPEC
- Assign severity (Critical/High/Medium/Low)
- Provide business impact
- Give concrete remediation steps
- Prioritize findings

Return an HTML report. No JavaScript.
IMPORTANT: Do NOT wrap the output in Markdown code fences (no ```).
"""
    return prompt.strip()

# ============================================================
# AI OUTPUT NORMALIZATION
# ============================================================
def strip_markdown_fences(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"^\s*```[a-zA-Z0-9_-]*\s*\n", "", text)
    text = re.sub(r"\n\s*```\s*$", "", text)
    text = text.replace("```html", "").replace("```HTML", "").replace("```", "")
    return text.strip()

def looks_like_full_html_document(text: str) -> bool:
    if not text:
        return False
    t = text.lstrip().lower()
    if "<html" in t and "</html>" in t:
        return True
    if t.startswith("<!doctype html"):
        return True
    return False

def strip_preamble(text: str) -> str:
    lower = text.lower()
    for marker in ("<!doctype", "<html"):
        idx = lower.find(marker)
        if idx > 0:
            return text[idx:]
    return text

def wrap_ai_html(ai_html: str, trust_ai_html: bool) -> str:
    ai_html = strip_markdown_fences(ai_html)
    if trust_ai_html and looks_like_full_html_document(ai_html):
        return strip_preamble(ai_html)
    body = ai_html if trust_ai_html else f"<pre>{escape(ai_html)}</pre>"
    tpl = Template("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CyberShield Security Report</title>
<style>
:root { --bg: #ffffff; --fg: #1f2937; --muted: #6b7280; --border: #e5e7eb; --critical: #7f1d1d; --high: #b91c1c; --medium: #f59e0b; --low: #2563eb; }
body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--fg); margin: 0; padding: 0; }
header { background: #111827; color: #f9fafb; padding: 24px 40px; }
header h1 { margin: 0; font-size: 22px; }
header .meta { font-size: 13px; color: #9ca3af; }
main { max-width: 1200px; margin: auto; padding: 40px; }
h2 { border-bottom: 2px solid var(--border); padding-bottom: 6px; }
.finding { border: 1px solid var(--border); border-left: 6px solid #9ca3af; padding: 16px; margin: 20px 0; background: #f9fafb; border-radius: 4px; }
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.severity { font-weight: bold; }
.severity.critical { color: var(--critical); }
.severity.high { color: var(--high); }
.severity.medium { color: var(--medium); }
.severity.low { color: var(--low); }
pre { background: #f3f4f6; padding: 12px; overflow-x: auto; border-radius: 4px; font-size: 13px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { border: 1px solid var(--border); padding: 8px; text-align: left; }
th { background: #f3f4f6; }
footer { text-align: center; color: var(--muted); font-size: 12px; padding: 40px; }
</style>
</head>
<body>
<header>
  <h1>CyberShield Security Report</h1>
  <div class="meta">Generated {{ timestamp }} • CyberShield-SecureScan • Authorized use only</div>
</header>
<main>{{ body | safe }}</main>
<footer>This report was automatically generated. Always validate findings before production decisions.</footer>
</body>
</html>
""")
    return tpl.render(body=body, timestamp=time.strftime("%Y-%m-%d %H:%M:%S"))

# ============================================================
# AI PROVIDERS
# ============================================================
def ask_groq(prompt: str, timeout: int = 60) -> str:
    if not GROQ_API_KEY:
        return "<b>Groq API key not configured.</b>"
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst."},
            {"role": "user", "content": prompt}
        ],
        "temperature": TEMPERATURE,
        "max_tokens": TOKEN_LIMIT,
    }
    try:
        r = HTTP_SESSION.post(url, headers=headers, json=payload, timeout=timeout)
        if r.status_code == 401:
            return "<b>Groq API error: Invalid API key.</b>"
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logging.error("Groq API error: %s", e)
        return "<b>Groq API error.</b>"

def ask_deepseek(prompt: str, timeout: int = 60) -> str:
    if not DEEPSEEK_API_KEY:
        return "<b>DeepSeek API key not configured.</b>"
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst."},
            {"role": "user", "content": prompt}
        ],
        "temperature": TEMPERATURE,
        "max_tokens": TOKEN_LIMIT,
    }
    try:
        r = HTTP_SESSION.post(url, headers=headers, json=payload, timeout=timeout)
        if r.status_code == 402:
            return "<b>DeepSeek API error: Payment required.</b>"
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logging.error("DeepSeek API error: %s", e)
        return "<b>DeepSeek API error.</b>"

def ask_ollama(prompt: str, timeout: int = 60) -> str:
    url = f"{OLLAMA_API_URL.rstrip('/')}/api/chat"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst."},
            {"role": "user", "content": prompt}
        ],
        "stream": False,
        "options": {"temperature": TEMPERATURE},
    }
    try:
        r = HTTP_SESSION.post(url, json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "<b>Ollama returned empty content.</b>")
    except Exception as e:
        logging.error("Ollama API error: %s", e)
        return "<b>Ollama API error.</b>"

def ask_openai(prompt: str, timeout: int = 60) -> str:
    if not OPENAI_API_KEY:
        return "<b>OpenAI API key not configured.</b>"
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior penetration tester and vulnerability analyst."},
            {"role": "user", "content": prompt}
        ],
        "temperature": TEMPERATURE,
        "max_tokens": TOKEN_LIMIT,
    }
    try:
        r = HTTP_SESSION.post(url, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logging.error("OpenAI API error: %s", e)
        return "<b>OpenAI API error.</b>"

def ask_provider(provider: str, prompt: str, timeout: int = 60) -> str:
    p = (provider or "groq").strip().lower()
    if p == "groq":
        return ask_groq(prompt, timeout)
    elif p == "deepseek":
        return ask_deepseek(prompt, timeout)
    elif p == "ollama":
        return ask_ollama(prompt, timeout)
    elif p == "openai":
        return ask_openai(prompt, timeout)
    else:
        return f"<b>Unknown provider: {provider}</b>"

# ============================================================
# Exporters
# ============================================================
def export_report_html(ai_html: str, filename: str, trust_ai_html: bool):
    html = wrap_ai_html(ai_html, trust_ai_html)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

def export_report_txt(ai_text: str, filename: str):
    ai_text = strip_markdown_fences(ai_text)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(ai_text)

def export_report_json(scan: Dict[str, Any], ai_output: str, filename: str, meta: Dict[str, Any]):
    ai_output = strip_markdown_fences(ai_output)
    payload = {"meta": meta, "scan": scan, "ai_output": ai_output}
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

def export_report_csv(scan: Dict[str, Any], ai_output: str, filename: str, meta: Dict[str, Any]):
    import csv
    rows = []
    for host in scan.get("hosts", []):
        addr = host.get("address") or ""
        hn = (host.get("hostnames") or [""])[0]
        for p in host.get("ports", []):
            rows.append({
                "target": meta.get("target", ""),
                "host_address": addr,
                "hostname": hn,
                "protocol": p.get("protocol"),
                "port": p.get("portid"),
                "state": p.get("state"),
                "service_name": (p.get("service") or {}).get("name", ""),
                "service_product": (p.get("service") or {}).get("product", ""),
                "service_version": (p.get("service") or {}).get("version", ""),
                "service_extrainfo": (p.get("service") or {}).get("extrainfo", ""),
            })
    fieldnames = ["target", "host_address", "hostname", "protocol", "port", "state",
                  "service_name", "service_product", "service_version", "service_extrainfo"]
    with open(filename, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

def export_report_xml(scan: Dict[str, Any], ai_output: str, filename: str, meta: Dict[str, Any]):
    ai_output = strip_markdown_fences(ai_output)
    root = ET.Element("ai_vulnerability_report")
    meta_el = ET.SubElement(root, "meta")
    for k, v in meta.items():
        child = ET.SubElement(meta_el, k)
        child.text = str(v)
    scan_el = ET.SubElement(root, "scan_json")
    scan_el.text = json.dumps(scan, ensure_ascii=False)
    ai_el = ET.SubElement(root, "ai_output")
    ai_el.text = ai_output
    ET.ElementTree(root).write(filename, encoding="utf-8", xml_declaration=True)

# ============================================================
# MAIN
# ============================================================
def setup_debug_logging(debug: bool, debug_log: Optional[str]):
    if not (debug or debug_log):
        return
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        root.addHandler(ch)
    if debug_log:
        fh = logging.FileHandler(debug_log, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
        logging.debug("Debug log file enabled: %s", debug_log)

def resolve_nmap_args(args: argparse.Namespace) -> Tuple[str, int, bool]:
    user_provided = hasattr(args, "nmap_args")
    profile = getattr(args, "profile", 1)
    if profile not in SCAN_PROFILES:
        raise ValueError(f"Invalid profile {profile}")
    if user_provided:
        return args.nmap_args, profile, False
    return SCAN_PROFILES[profile], profile, True

def build_output_filename(target: str, output_format: str) -> str:
    ts = int(time.time())
    safe_target = re.sub(r"[^a-zA-Z0-9._-]+", "_", target)
    return f"{safe_target}-{ts}.{output_format}"

def main():
    print_ethical_warning()
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--nmap-path", default=None)
    parser.add_argument("--nmap-args", default=argparse.SUPPRESS)
    parser.add_argument("--provider", default="groq", help="AI provider: groq, deepseek, ollama, openai")
    parser.add_argument("--ai-timeout", type=int, default=120)
    parser.add_argument("--trust-ai-html", action="store_true")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-dl", "--debug-log", nargs="?", const="vulnscanner-debug.log")
    parser.add_argument("-o", "--output", choices=["html", "csv", "xml", "txt", "json"], default="html")
    parser.add_argument("-p", "--profile", type=int, default=1)
    parser.add_argument("--list-profiles", action="store_true")

    args = parser.parse_args()
    setup_debug_logging(args.debug, args.debug_log)

    if args.list_profiles:
        print("Available scan profiles:")
        for num, profile_args in sorted(SCAN_PROFILES.items()):
            print(f"  Profile {num}: {profile_args}")
        sys.exit(0)

    if not args.target:
        parser.error("the following arguments are required: -t/--target")

    validate_api_keys(args.provider)
    target = sanitize_target(args.target)
    if not is_safe_target(target):
        logging.error("Invalid target.")
        sys.exit(1)

    try:
        nmap_bin = ensure_nmap_available(args.nmap_path)
    except Exception as e:
        logging.error("%s", e)
        sys.exit(1)

    try:
        nmap_args, profile_used, used_profile_flag = resolve_nmap_args(args)
        if used_profile_flag:
            logging.info("Using scan profile %s: %s", profile_used, nmap_args)
        else:
            logging.info("Using custom --nmap-args: %s", nmap_args)
    except Exception as e:
        logging.error("%s", e)
        sys.exit(1)

    scan = run_nmap_scan(nmap_bin, target, nmap_args)
    if not scan:
        logging.error("No scan results.")
        sys.exit(2)

    open_ports = extract_open_ports(scan)
    logging.info("Open ports: %s", open_ports)

    # TCI Analysis
    tci_result = None
    if TCI_AVAILABLE:
        try:
            tci_result = get_tci_plan(scan)
            logging.info("TCI Score: %d/100 (Severity: %s)", 
                        tci_result.get('tci_score', 0), 
                        tci_result.get('severity', 'unknown').upper())
        except Exception as e:
            logging.warning("TCI analysis failed: %s", e)

    # History Database
    if HISTORY_AVAILABLE:
        try:
            meta_for_db = {
                'target': target,
                'provider': args.provider,
                'report_file': 'pending',
                'tci_score': tci_result.get('tci_score', 0) if tci_result else 0,
                'tci_severity': tci_result.get('severity', 'unknown') if tci_result else 'unknown',
                'vulnerabilities': []
            }
            store_scan_result(scan, meta_for_db)
            logging.info("Scan results stored in history database")
            
            try:
                trends = detect_trends(target)
                if trends.get('scan_count', 0) >= 2:
                    logging.info("Trend: TCI=%s, Severity=%s", 
                                trends.get('tci_direction', 'unknown'),
                                trends.get('severity_direction', 'unknown'))
            except Exception:
                pass
        except Exception as e:
            logging.warning("History storage failed: %s", e)

    # AI Analysis
    MAX_SCAN_JSON_CHARS = 100000
    scan_json_str = json.dumps(scan, indent=2)
    if len(scan_json_str) > MAX_SCAN_JSON_CHARS:
        scan_json_str = scan_json_str[:MAX_SCAN_JSON_CHARS] + "\n... [truncated]"

    prompt = build_ai_prompt(scan, open_ports, target, _scan_json=scan_json_str, tci_result=tci_result)
    provider = args.provider
    logging.info("Sending to %s API...", provider)
    ai_output = ask_provider(provider, prompt, timeout=args.ai_timeout)

    if not ai_output:
        logging.error("AI returned empty output.")
        sys.exit(3)

    outfile = build_output_filename(target, args.output)
    meta = {
        "target": target,
        "provider": provider,
        "output_format": args.output,
        "profile": args.profile,
        "nmap_args": nmap_args,
        "trust_ai_html": bool(args.trust_ai_html),
        "timestamp": int(time.time()),
    }

    fmt = args.output.lower()
    if fmt == "html":
        export_report_html(ai_output, outfile, args.trust_ai_html)
    elif fmt == "txt":
        export_report_txt(ai_output, outfile)
    elif fmt == "json":
        export_report_json(scan, ai_output, outfile, meta)
    elif fmt == "csv":
        export_report_csv(scan, ai_output, outfile, meta)
    elif fmt == "xml":
        export_report_xml(scan, ai_output, outfile, meta)

    print(f"Scan complete. Output written to {outfile}")

if __name__ == "__main__":
    main()
