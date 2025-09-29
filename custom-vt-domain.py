#!/usr/bin/env python3

import sys, json, time, os, requests
from urllib.parse import urlparse

# Config
RATE_LIMIT_FILE = "/var/ossec/logs/vt_rate_limit_domain.json"
MAX_REQUESTS_PER_MINUTE = 4
DEBUG_LOG = "/var/ossec/logs/vt-domain-debug.log"
INTEGRATION_OUTPUT = "/var/ossec/logs/vt-integration-output.log"
REQUEST_TIMEOUT = 20

# Whitelist
WHITELIST_DOMAINS = [
    "connectivity-check.ubuntu.com",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "changelogs.ubuntu.com",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "youtube.com",
    "ytimg.com",
    "clients.google.com",
    "accounts.google.com",
    "ssl.gstatic.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "outlook.com",
    "ocsp.",
    "crl.",
    "openai.com",
    "chatgpt",
    "v0.dev",
    "vercel.com",
    "github.com",
    "stackoverflow.com",
    "virustotal.com",
    "malwarebytes.com",
    "kaspersky.com",
    "symantec.com",
    "cloudflare.com",
    "amazonaws.com",
    "azure.com",
    "fastly.com",
    "jsdelivr.net",
    "cdnjs.cloudflare.com",
    "detectportal.firefox.com", "gstatic.com",
    "googlesyndication.com", "googleads.g.doubleclick.net", "doubleclick.net",
    "mozilla.com", "mozilla.org", "push.services.mozilla.com",
    "merino.services.mozilla.com", "cdn.fwupd.org"
]

# Threshold rule (same as custom-vt-url)
# mark malicious if: mal_count >= 2 OR susp_count >= 5 OR total_positives >= 3

def setup_debug():
    try:
        f = open(DEBUG_LOG, "a")
        return f
    except Exception:
        return sys.stderr

def write_debug(f, msg):
    try:
        f.write(f"{time.time()}: {msg}\n")
        f.flush()
    except Exception:
        pass

def is_whitelisted(domain):
    if not domain:
        return True
    d = domain.lower().strip()
    if d.endswith('.'):
        d = d[:-1]
    # remove leading www
    if d.startswith("www."):
        d = d[4:]
    for w in WHITELIST_DOMAINS:
        if w.endswith('.'):
            if d.startswith(w):
                return True
        else:
            if d == w or d.endswith('.' + w) or w in d:
                # w in d keeps "chatgpt" and "google" style coverage
                return True
    return False

# Rate limit helpers
def load_rate():
    try:
        if os.path.exists(RATE_LIMIT_FILE):
            with open(RATE_LIMIT_FILE, "r") as f:
                obj = json.load(f)
                return obj.get("requests", [])
    except Exception:
        pass
    return []

def save_rate(list_ts):
    try:
        os.makedirs(os.path.dirname(RATE_LIMIT_FILE), exist_ok=True)
        with open(RATE_LIMIT_FILE, "w") as f:
            json.dump({"requests": list_ts}, f)
    except Exception:
        pass

def can_request():
    now = int(time.time())
    reqs = load_rate()
    # keep last 60s
    reqs = [r for r in reqs if now - int(r) < 60]
    if len(reqs) >= MAX_REQUESTS_PER_MINUTE:
        return False, reqs
    reqs.append(now)
    save_rate(reqs)
    return True, reqs

# VT v2 domain report
def vt_domain_report_v2(domain, api_key):
    vt_url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {"apikey": api_key, "domain": domain}
    try:
        ok, _ = can_request()
        if not ok:
            return 429, {"error": "local rate limited"}
        r = requests.get(vt_url, params=params, timeout=REQUEST_TIMEOUT)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        return r.status_code, data
    except Exception as e:
        return 520, {"error": str(e)}

# Analyze VT domain report (robust to response structure)
def analyze_domain_response(data):
    # Attempt to derive "positives"/"malicious"/"suspicious" style metrics
    mal_count = 0
    susp_count = 0
    total_positives = 0
    total_seen = 0

    # v2 domain report often contains "detected_urls": list of {url, positives, total}
    detected_urls = data.get("detected_urls") or data.get("detected_communicating_samples") or []
    if isinstance(detected_urls, dict):
        # some variants return mapping
        detected_urls = list(detected_urls.values())

    if detected_urls:
        for item in detected_urls:
            positives = int(item.get("positives", 0) or 0)
            total = int(item.get("total", 0) or 0)
            total_positives += positives
            total_seen += 1
            if positives >= 2:
                mal_count += 1
            elif positives == 1:
                susp_count += 1

    # Fallback: some VT domain reports include last_analysis_stats under "last_analysis_stats"
    last_stats = data.get("last_analysis_stats") or (data.get("data", {}) .get("attributes", {}).get("last_analysis_stats") if isinstance(data.get("data", {}), dict) else None)
    if last_stats and isinstance(last_stats, dict):
        try:
            mal_count_from_stats = int(last_stats.get("malicious", 0) or 0)
            susp_count_from_stats = int(last_stats.get("suspicious", 0) or 0)
            undetected = int(last_stats.get("undetected", 0) or 0)
            # use these numbers as additional signal
            total_positives = max(total_positives, mal_count_from_stats + susp_count_from_stats)
            mal_count = max(mal_count, mal_count_from_stats)
            susp_count = max(susp_count, susp_count_from_stats)
        except Exception:
            pass

    # Also check if response has a 'positives' field (uncommon for domain but handle)
    if "positives" in data:
        try:
            p = int(data.get("positives", 0) or 0)
            total_positives = max(total_positives, p)
        except:
            pass

    return mal_count, susp_count, total_positives, total_seen

def build_integration_output(domain, malicious_flag, stats, src_ip, dest_ip):
    return {
        "integration": "custom-vt-domain",
        "domain": domain,
        "malicious": bool(malicious_flag),
        "stats": stats,
        "timestamp": time.time(),
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "endpoint_ip": src_ip
    }

def main():
    if len(sys.argv) < 3:
        sys.exit(0)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    debug = setup_debug()

    write_debug(debug, f"SCRIPT STARTED - Processing {alert_file}")

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            raw = f.read()
            write_debug(debug, f"RAW ALERT: {raw[:300]}")
            alert = json.loads(raw)
    except Exception as e:
        write_debug(debug, f"Error reading/parsing alert file: {e}")
        return

    # try multiple locations for Suricata data
    data_section = alert.get("data") or alert.get("_source", {}).get("data") or alert

    # try extract src/dest ips robustly
    src_ip = data_section.get("src_ip") or alert.get("src_ip") or alert.get("_source", {}).get("src_ip", "")
    dest_ip = data_section.get("dest_ip") or alert.get("dest_ip") or alert.get("_source", {}).get("dest_ip", "")

    write_debug(debug, f"IP INFO - Source: {src_ip}, Destination: {dest_ip}")

    # Extract domain from TLS SNI
    domain = None
    try:
        if data_section.get("event_type") == "tls":
            tls = data_section.get("tls") or {}
            domain = tls.get("sni") or tls.get("server_name") or None
        # If not tls, check dns
        if not domain and data_section.get("event_type") == "dns":
            dns = data_section.get("dns") or {}
            # field may be 'rrname', 'query', 'qname'
            domain = dns.get("rrname") or dns.get("query") or dns.get("qname") or None

        # fallback: if data_section contains nested suricata event
        if not domain:
            # walk some possible nested structures
            for k in ("tls", "dns"):
                if k in data_section:
                    part = data_section.get(k) or {}
                    possible = part.get("sni") or part.get("rrname") or part.get("query") or part.get("qname")
                    if possible:
                        domain = possible
                        break
    except Exception as e:
        write_debug(debug, f"Error extracting domain: {e}")

    if not domain:
        write_debug(debug, "No domain found in alert; exiting")
        return

    # normalize domain
    domain = domain.strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]

    write_debug(debug, f"Domain extracted: {domain}")

    # whitelist check
    if is_whitelisted(domain):
        write_debug(debug, f"WHITELISTED {domain}")
        return

    # call VT domain report (v2)
    write_debug(debug, f"Checking domain on VirusTotal: {domain}")

    sc, resp = vt_domain_report_v2(domain, api_key)
    write_debug(debug, f"VT API Response Code: {sc}")
    if sc == 429:
        write_debug(debug, f"RATE LIMITED (local or remote) for {domain}")
        return

    if sc != 200:
        write_debug(debug, f"VT API returned non-200 ({sc}) for {domain} - resp excerpt: {str(resp)[:200]}")
        return

    write_debug(debug, f"VT API Response: {json.dumps(resp)[:800]}")

    # analyze response
    mal_count, susp_count, total_positives, total_seen = analyze_domain_response(resp)
    write_debug(debug, f"ANALYSIS - Malicious: {mal_count}, Suspicious: {susp_count}, TotalPositives: {total_positives}, SeenUrls: {total_seen}")

    # decide malicious per same threshold
    is_malicious = (mal_count >= 2) or (susp_count >= 5) or (total_positives >= 3)

    stats = {
        "malicious": mal_count,
        "suspicious": susp_count,
        "total_positives": total_positives,
        "seen_urls": total_seen
    }

    if is_malicious:
        write_debug(debug, f"MALICIOUS DETECTED: {domain} - {stats}")
        integration_output = build_integration_output(domain, True, stats, src_ip, dest_ip)
        # write integration output file
        try:
            os.makedirs(os.path.dirname(INTEGRATION_OUTPUT), exist_ok=True)
            with open(INTEGRATION_OUTPUT, "a") as outf:
                outf.write(json.dumps(integration_output) + "\n")
                outf.flush()
            write_debug(debug, f"MALICIOUS ALERT WRITTEN TO INTEGRATION LOG WITH IP: {src_ip}")
        except Exception as e:
            write_debug(debug, f"ERROR writing integration output: {e}")
        # print to stdout so Wazuh will create alert
        print(json.dumps(integration_output))
    else:
        write_debug(debug, f"CLEAN {domain} {stats}")

    # done
    try:
        if debug != sys.stderr:
            debug.close()
    except:
        pass

if __name__ == "__main__":
    main()
