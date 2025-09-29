#!/usr/bin/env python3

import sys
import json
import requests
import time
import os
import hashlib
from urllib.parse import urlparse
import re

# Rate limiting configuration
RATE_LIMIT_FILE = "/var/ossec/logs/vt_rate_limit.json"  # moved to ossec logs directory for proper permissions
MAX_REQUESTS_PER_MINUTE = 4
REQUEST_INTERVAL = 60 / MAX_REQUESTS_PER_MINUTE  # 15 seconds between requests

# Whitelist domains
WHITELIST_DOMAINS = [
    # Ubuntu/System
    "connectivity-check.ubuntu.com",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "changelogs.ubuntu.com",
    
    # Google Services
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
    
    # Microsoft
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "outlook.com",
    
    # Security/Certificate validation
    "ocsp.",  # OCSP validation
    "crl.",   # Certificate Revocation Lists
    
    # Development/AI Tools
    "openai.com",
    "chatgpt.com",
    "v0.dev",
    "vercel.com",
    "github.com",
    "stackoverflow.com",
    
    # Security vendors
    "virustotal.com",
    "malwarebytes.com",
    "kaspersky.com",
    "symantec.com",
    
    # CDNs and common services
    “detectportal.firefox.com”,
    "cloudflare.com",
    "amazonaws.com",
    "azure.com",
    "fastly.com",
    "jsdelivr.net",
    "cdnjs.cloudflare.com"
]

def setup_logging():
    """Setup debug logging"""
    try:
        debug_file = open("/var/ossec/logs/vt-url-debug.log", "a")
        return debug_file
    except Exception as e:
        # Fallback to stderr if can't open debug file
        return sys.stderr

def is_whitelisted(url):
    """Check if URL is in whitelist"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Check exact matches and wildcard matches
        for whitelist_domain in WHITELIST_DOMAINS:
            if whitelist_domain.endswith('.'):
                # Wildcard match (e.g., "ocsp.")
                if domain.startswith(whitelist_domain):
                    return True
            else:
                # Exact match or subdomain match
                if domain == whitelist_domain or domain.endswith('.' + whitelist_domain):
                    return True
                    
        return False
    except Exception as e:
        return False

def load_rate_limit_data():
    """Load rate limiting data from file"""
    try:
        if os.path.exists(RATE_LIMIT_FILE):
            with open(RATE_LIMIT_FILE, 'r') as f:
                data = json.load(f)
                return data.get('requests', [])
    except Exception as e:
        pass
    return []

def save_rate_limit_data(requests_log):
    """Save rate limiting data to file"""
    try:
        os.makedirs(os.path.dirname(RATE_LIMIT_FILE), exist_ok=True)
        with open(RATE_LIMIT_FILE, 'w') as f:
            json.dump({'requests': requests_log}, f)
    except Exception as e:
        # Silently fail if can't save rate limit data
        pass

def can_make_request():
    """Check if we can make a request based on rate limiting"""
    current_time = time.time()
    requests_log = load_rate_limit_data()
    
    # Remove requests older than 1 minute
    requests_log = [req_time for req_time in requests_log if current_time - req_time < 60]
    
    # Check if we can make a new request
    if len(requests_log) >= MAX_REQUESTS_PER_MINUTE:
        return False, requests_log
    
    return True, requests_log

def record_request():
    """Record a new request timestamp"""
    current_time = time.time()
    requests_log = load_rate_limit_data()
    
    # Remove old requests and add new one
    requests_log = [req_time for req_time in requests_log if current_time - req_time < 60]
    requests_log.append(current_time)
    
    save_rate_limit_data(requests_log)

def wait_for_rate_limit():
    """Wait until we can make a request"""
    while True:
        can_request, requests_log = can_make_request()
        if can_request:
            break
            
        # Calculate wait time
        if requests_log:
            oldest_request = min(requests_log)
            wait_time = 60 - (time.time() - oldest_request) + 1
            if wait_time > 0:
                time.sleep(wait_time)
        else:
            break

def check_virustotal(url, api_key, debug_file):
    """Check URL reputation with VirusTotal API"""
    
    # Check whitelist first
    if is_whitelisted(url):
        print(f"{time.time()}: WHITELISTED {url}", file=debug_file)
        debug_file.flush()
        return False, {"whitelisted": True}
    
    print(f"{time.time()}: CHECKING URL: {url}", file=debug_file)
    debug_file.flush()
    
    # Rate limiting check
    wait_for_rate_limit()
    
    try:
        # Record this request
        record_request()
        
        # VirusTotal API v2 URL report
        vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {
            'apikey': api_key,
            'resource': url
        }
        
        response = requests.get(vt_url, params=params, timeout=30)
        print(f"{time.time()}: VT API Response Code: {response.status_code}", file=debug_file)
        
        if response.status_code == 429:
            print(f"{time.time()}: RATE LIMITED - Skipping check for {url}", file=debug_file)
            debug_file.flush()
            return False, {"rate_limited": True}
        
        if response.status_code != 200:
            print(f"{time.time()}: API ERROR {response.status_code} for {url}", file=debug_file)
            debug_file.flush()
            return False, {"api_error": response.status_code}
        
        data = response.json()
        print(f"{time.time()}: RAW VT RESPONSE: {json.dumps(data)[:200]}...", file=debug_file)
        
        if data.get('response_code') == 1:
            # URL found in VirusTotal database
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            
            # Get detailed scan results
            scans = data.get('scans', {})
            malicious_vendors = []
            suspicious_vendors = []
            
            for vendor, result in scans.items():
                if result.get('detected'):
                    result_text = result.get('result', '').lower()
                    if any(keyword in result_text for keyword in ['malware', 'trojan', 'virus', 'malicious']):
                        malicious_vendors.append(vendor)
                    else:
                        suspicious_vendors.append(vendor)
            
            mal_count = len(malicious_vendors)
            susp_count = len(suspicious_vendors)
            
            print(f"{time.time()}: ANALYSIS - Malicious: {mal_count}, Suspicious: {susp_count}, Total: {total}", file=debug_file)
            
            stats = {
                'malicious': mal_count,
                'suspicious': susp_count,
                'total': total,
                'positives': positives,
                'malicious_vendors': malicious_vendors[:5],  # Limit output
                'suspicious_vendors': suspicious_vendors[:5]
            }
            
            # Lower threshold: 2+ malicious OR 5+ suspicious detections
            is_malicious = mal_count >= 2 or susp_count >= 5 or positives >= 3
            
            if is_malicious:
                print(f"{time.time()}: MALICIOUS DETECTED: {url} - {stats}", file=debug_file)
            else:
                print(f"{time.time()}: CLEAN {url} {stats}", file=debug_file)
                
            debug_file.flush()
            return is_malicious, stats
            
        else:
            # URL not found in database
            print(f"{time.time()}: URL NOT FOUND in VT database: {url}", file=debug_file)
            debug_file.flush()
            return False, {"not_found": True}
            
    except Exception as e:
        print(f"{time.time()}: ERROR checking {url}: {str(e)}", file=debug_file)
        debug_file.flush()
        return False, {"error": str(e)}

def main():
    if len(sys.argv) < 3:
        sys.exit(1)
    
    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    
    debug_file = setup_logging()
    
    try:
        print(f"{time.time()}: SCRIPT STARTED - Processing {alert_file}", file=debug_file)
        debug_file.flush()
        
        with open(alert_file, 'r') as f:
            alert_content = f.read()
            print(f"{time.time()}: RAW ALERT CONTENT: {alert_content[:200]}...", file=debug_file)
            debug_file.flush()
            
            # Parse JSON
            alert_data = json.loads(alert_content)
        
        # Try multiple paths to find IP information
        data_section = alert_data.get('data', {})
        if not data_section:
            data_section = alert_data.get('_source', {}).get('data', {})
        
        # Extract source and destination IPs
        src_ip = data_section.get('src_ip', '')
        dest_ip = data_section.get('dest_ip', '')
        
        # Also try alternative paths for IP
        if not src_ip:
            src_ip = alert_data.get('src_ip', '') or alert_data.get('_source', {}).get('src_ip', '')
        if not dest_ip:
            dest_ip = alert_data.get('dest_ip', '') or alert_data.get('_source', {}).get('dest_ip', '')
        
        print(f"{time.time()}: IP INFO - Source: {src_ip}, Destination: {dest_ip}", file=debug_file)
        debug_file.flush()
        
        # Extract URL from Suricata HTTP event
        http_data = alert_data.get('data', {}).get('http', {})
        if not http_data:
            # Try alternative paths
            http_data = alert_data.get('http', {})
            if not http_data:
                http_data = alert_data.get('_source', {}).get('data', {}).get('http', {})
        
        print(f"{time.time()}: HTTP DATA EXTRACTED: {json.dumps(http_data)}", file=debug_file)
        debug_file.flush()
        
        hostname = http_data.get('hostname', '')
        url_path = http_data.get('url', '/')
        
        if not hostname:
            print(f"{time.time()}: NO HOSTNAME found in alert - trying alternative fields", file=debug_file)
            hostname = http_data.get('host', '') or http_data.get('server_name', '')
            
        if not hostname:
            print(f"{time.time()}: NO HOSTNAME found anywhere in alert", file=debug_file)
            debug_file.flush()
            sys.exit(0)
        
        # Construct full URL
        if url_path.startswith('http'):
            full_url = url_path
        else:
            full_url = f"http://{hostname}{url_path}"
        
        print(f"{time.time()}: CONSTRUCTED URL: {full_url}", file=debug_file)
        debug_file.flush()
        
        # Check with VirusTotal
        is_malicious, stats = check_virustotal(full_url, api_key, debug_file)
        
        if is_malicious:
            integration_output = {
                "integration": "custom-vt-url",
                "url": full_url,
                "malicious": True,
                "stats": stats,
                "timestamp": time.time(),
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "endpoint_ip": src_ip  # Usually source IP is the endpoint accessing the malicious site
            }
            
            # Write to integration output file
            try:
                with open("/var/ossec/logs/vt-integration-output.log", "a") as output_file:
                    output_file.write(json.dumps(integration_output) + "\n")
                    output_file.flush()
                print(f"{time.time()}: MALICIOUS ALERT WRITTEN TO INTEGRATION LOG WITH IP: {src_ip}", file=debug_file)
            except Exception as e:
                print(f"{time.time()}: ERROR writing to integration log: {e}", file=debug_file)
            
            # Also output to stdout for backward compatibility
            print(json.dumps(integration_output))
            print(f"{time.time()}: OUTPUT SENT TO WAZUH WITH IP INFO: {json.dumps(integration_output)}", file=debug_file)
        else:
            print(f"{time.time()}: URL CLEAN - No output sent to Wazuh", file=debug_file)
        
        debug_file.flush()
        
    except Exception as e:
        print(f"{time.time()}: MAIN ERROR: {str(e)}", file=debug_file)
        print(f"{time.time()}: EXCEPTION TYPE: {type(e).__name__}", file=debug_file)
        import traceback
        print(f"{time.time()}: TRACEBACK: {traceback.format_exc()}", file=debug_file)
        debug_file.flush()
    finally:
        if debug_file != sys.stderr:
            debug_file.close()

if __name__ == "__main__":
    main()
