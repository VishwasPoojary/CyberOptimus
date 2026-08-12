import socket
import time
import requests
import re
from typing import Tuple, Dict, Any, Optional
import urllib3
import ssl
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Disable warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def resolve_ip(domain: str) -> str:
    """Resolves a domain name to an IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "Unable to resolve IP"

def normalize_input_url(target: str) -> str:
    """Normalizes any input URL string (google.com, www.google.com, HTTP://GOOGLE.COM) into a canonical URL."""
    if not target:
        return ""
    u = target.strip()
    u_lower = u.lower()
    
    if u_lower.startswith("http://"):
        scheme = "http://"
        rest = u[7:]
    elif u_lower.startswith("https://"):
        scheme = "https://"
        rest = u[8:]
    else:
        scheme = "https://"
        rest = u
        
    if "/" in rest:
        host, path = rest.split("/", 1)
        path = "/" + path
    else:
        host = rest
        path = ""
        
    host = host.lower()
    return f"{scheme}{host}{path}"

import dns.resolver

def query_dns_records(domain: str) -> dict:
    """Queries comprehensive public DNS records (A, AAAA, MX, NS, TXT, CNAME, SPF, DMARC, DNSSEC)."""
    res = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
        "spf": {"present": False, "status": "missing", "record": None, "valid": False, "error": None},
        "dmarc": {"present": False, "status": "missing", "policy": "none", "record": None, "error": None},
        "dnssec": False,
        "query_errors": {},
        "error": None
    }
    if not domain or domain in ["Unable to resolve IP", "Unknown"]:
        res["error"] = "Invalid domain name"
        return res

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    txt_lookup_failed = False
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            ans = resolver.resolve(domain, rtype)
            for rdata in ans:
                if rtype == "TXT" and hasattr(rdata, "strings"):
                    val = "".join(s.decode('utf-8', errors='ignore') for s in rdata.strings)
                else:
                    val = str(rdata).strip('"')
                res[rtype].append(val)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception as e:
            res["query_errors"][rtype] = str(e)
            if rtype == "TXT":
                txt_lookup_failed = True

    from app.utils.domain_intelligence import extract_registered_domain
    reg_domain = extract_registered_domain(domain)

    # DMARC query via _dmarc.<domain> (with organizational fallback)
    dmarc_domains_to_try = [f"_dmarc.{domain}"]
    if reg_domain and reg_domain != domain:
        dmarc_domains_to_try.append(f"_dmarc.{reg_domain}")

    for target_dmarc_domain in dmarc_domains_to_try:
        try:
            ans = resolver.resolve(target_dmarc_domain, "TXT")
            for rdata in ans:
                if hasattr(rdata, "strings"):
                    txt = "".join(s.decode('utf-8', errors='ignore') for s in rdata.strings)
                else:
                    txt = str(rdata).strip('"')
                if "v=DMARC1" in txt.upper():
                    res["dmarc"]["present"] = True
                    res["dmarc"]["status"] = "present"
                    if target_dmarc_domain != f"_dmarc.{domain}":
                        res["dmarc"]["record"] = f"Inherited from organizational domain ({reg_domain}): {txt}"
                        res["dmarc"]["inherited_from"] = reg_domain
                    else:
                        res["dmarc"]["record"] = txt
                    policy_match = re.search(r'p=\s*([a-zA-Z]+)', txt)
                    if policy_match:
                        res["dmarc"]["policy"] = policy_match.group(1).lower()
                    break
            if res["dmarc"]["present"]:
                break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            res["dmarc"]["status"] = "missing"
        except Exception as e:
            if not res["dmarc"]["present"]:
                res["dmarc"]["status"] = "error"
                res["dmarc"]["error"] = str(e)

    # Check SPF in TXT records (with organizational fallback)
    if txt_lookup_failed:
        res["spf"]["status"] = "error"
        res["spf"]["error"] = res["query_errors"].get("TXT", "DNS TXT lookup failed")
    else:
        for txt in res["TXT"]:
            if "v=spf1" in txt.lower():
                res["spf"]["present"] = True
                res["spf"]["status"] = "present"
                res["spf"]["record"] = txt
                res["spf"]["valid"] = True
                break
        if not res["spf"]["present"] and reg_domain and reg_domain != domain:
            try:
                parent_ans = resolver.resolve(reg_domain, "TXT")
                for rdata in parent_ans:
                    if hasattr(rdata, "strings"):
                        p_txt = "".join(s.decode('utf-8', errors='ignore') for s in rdata.strings)
                    else:
                        p_txt = str(rdata).strip('"')
                    if "v=spf1" in p_txt.lower():
                        res["spf"]["present"] = True
                        res["spf"]["status"] = "present"
                        res["spf"]["record"] = f"Inherited from organizational domain ({reg_domain}): {p_txt}"
                        res["spf"]["valid"] = True
                        res["spf"]["inherited_from"] = reg_domain
                        break
            except Exception:
                pass

        if not res["spf"]["present"]:
            res["spf"]["status"] = "missing"

    # Fallback A record lookup via socket if resolver returned empty
    if not res["A"]:
        try:
            ip = socket.gethostbyname(domain)
            if ip:
                res["A"].append(ip)
        except Exception:
            pass

    return res

def fetch_rdap_domain_info(domain: str) -> dict:
    """Fetches public domain registration data (age, creation date, expiration, registrar) via RDAP with graceful fallback."""
    info = {
        "rdap_available": False,
        "domain": domain,
        "creation_date": None,
        "expiration_date": None,
        "registrar": "Unknown",
        "domain_age_days": None,
        "error": None
    }
    if not domain or "." not in domain:
        info["error"] = "Invalid domain format"
        return info

    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            info["rdap_available"] = True
            
            # Extract events (registration, expiration)
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
            reg_date_str = events.get("registration") or events.get("last changed")
            exp_date_str = events.get("expiration")
            
            if reg_date_str:
                info["creation_date"] = reg_date_str[:10]
                try:
                    dt = datetime.datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                    now = datetime.datetime.now(datetime.timezone.utc)
                    info["domain_age_days"] = (now - dt).days
                except Exception:
                    pass
                    
            if exp_date_str:
                info["expiration_date"] = exp_date_str[:10]
                
            # Extract registrar entities
            entities = data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if len(item) > 3 and item[0] == "fn":
                                info["registrar"] = item[3]
                                break
        else:
            info["error"] = f"RDAP returned status {resp.status_code}"
    except Exception as e:
        info["error"] = f"RDAP request exception: {str(e)}"
        
    return info

def fetch_html_content(url: str, timeout: int = 5) -> Tuple[Optional[str], Optional[requests.Response], Optional[Exception]]:
    """Fetches full HTML page content for content security and login form inspection."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberOptimusReconEngine/1.0"
        }
        response = requests.get(url, timeout=timeout, verify=False, headers=headers)
        # Limit text content read to 2MB to prevent memory exhaustion
        html_text = response.text[:2000000] if response.text else ""
        return html_text, response, None
    except requests.RequestException as e:
        return None, None, e

def fetch_url(url: str, timeout: int = 5) -> Tuple[Optional[requests.Response], Optional[Exception]]:
    """Fetches a URL bypassing TLS validation using HEAD request with GET fallback if HEAD fails or returns 403/405."""
    try:
        head_resp = requests.head(url, timeout=timeout, verify=False, allow_redirects=True)
        if head_resp.status_code not in (403, 405, 501) and len(head_resp.headers) > 3:
            return head_resp, None
    except requests.RequestException:
        pass
        
    try:
        get_resp = requests.get(url, timeout=timeout, verify=False, stream=True)
        return get_resp, None
    except requests.RequestException as e:
        return None, e

def check_ssl_certificate(domain: str) -> dict:
    """Checks the SSL certificate of a given domain using cryptography for parsing."""
    result = {
        "valid": False,
        "issuer": "Unknown",
        "expiration": "Unknown",
        "tls_version": "N/A",
        "subject": "N/A",
        "days_remaining": "N/A",
        "san": [],
        "cipher_suite": "N/A",
        "ocsp_stapled": False,
        "sct_present": False,
        "error": None
    }
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    hosts_to_try = [domain]
    if not domain.startswith("www.") and domain.count(".") == 1:
        hosts_to_try.append(f"www.{domain}")

    cert_bin = None
    connected_host = None
    last_error = None

    for target_host in hosts_to_try:
        try:
            with socket.create_connection((target_host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    result["tls_version"] = ssock.version()
                    connected_host = target_host

                    try:
                        ciph = ssock.cipher()
                        if ciph:
                            result["cipher_suite"] = f"{ciph[0]} ({ciph[1]}, {ciph[2]} bits)"
                    except Exception:
                        pass

                    try:
                        ocsp_resp = ssock.ocsp_response
                        if ocsp_resp and len(ocsp_resp) > 0:
                            result["ocsp_stapled"] = True
                    except Exception:
                        pass

                    break
        except Exception as e:
            last_error = e

    if not cert_bin:
        result["error"] = f"Connection failed: {str(last_error)}" if last_error else "SSL connection failed"
        return result

    try:
        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
        
        try:
            sct_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
            cert.extensions.get_extension_for_oid(sct_oid)
            result["sct_present"] = True
        except Exception:
            result["sct_present"] = False

        try:
            issuer_attributes = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if not issuer_attributes:
                issuer_attributes = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            if issuer_attributes:
                result["issuer"] = issuer_attributes[0].value
        except Exception:
            pass

        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            o = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            parts = []
            if cn: parts.append(f"CN={cn[0].value}")
            if o: parts.append(f"O={o[0].value}")
            result["subject"] = ", ".join(parts) if parts else "Unknown"
        except Exception:
            pass

        not_after = cert.not_valid_after_utc
        if not_after:
            result["expiration"] = not_after.strftime("%Y-%m-%d")
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            days_left = (not_after - now_utc).days
            result["days_remaining"] = max(0, days_left)

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_domains = san_ext.value.get_values_for_type(x509.DNSName)
            result["san"] = san_domains
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"Certificate parsing failed: {str(e)}"
        return result

    verify_context = ssl.create_default_context()
    target_to_verify = connected_host or domain
    try:
        with socket.create_connection((target_to_verify, 443), timeout=5) as sock:
            with verify_context.wrap_socket(sock, server_hostname=target_to_verify) as ssock:
                result["valid"] = True
    except ssl.SSLCertVerificationError as e:
        error_msg = str(e).lower()
        if "certificate has expired" in error_msg:
            result["error"] = "Expired certificate"
        elif "self signed certificate" in error_msg or "self-signed certificate" in error_msg:
            result["error"] = "Self-signed certificate"
        elif "hostname mismatch" in error_msg or "doesn't match" in error_msg:
            result["error"] = "Hostname mismatch"
        elif "unable to get local issuer certificate" in error_msg or "certificate verify failed" in error_msg:
            result["error"] = "Untrusted or revoked certificate"
        else:
            result["error"] = getattr(e, 'verify_message', "Certificate verification failed")
    except ConnectionResetError:
        result["error"] = "Connection reset by peer"
    except Exception as e:
        # If verification socket fails on strict validation, fallback to cert validity check
        if result.get("days_remaining", 0) > 0 and result.get("issuer") != "Unknown":
            result["valid"] = True
        else:
            result["error"] = str(e)

    return result

def has_ipv6(domain: str) -> bool:
    """Checks if a domain resolves to an IPv6 address."""
    try:
        # Resolve AAAA records
        info = socket.getaddrinfo(domain, None, socket.AF_INET6)
        return len(info) > 0
    except Exception:
        return False

def measure_network_timings(url: str) -> dict:
    """Measures fine-grained network timings (DNS, TCP, TLS, TTFB, Download, Total)."""
    parsed = urllib3.util.parse_url(url)
    host = parsed.host
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    timings = {
        "dns_lookup": 0.0,
        "tcp_connect": 0.0,
        "tls_handshake": 0.0,
        "ttfb": 0.0,
        "download_time": 0.0,
        "total_time": 0.0
    }
    
    try:
        # 1. DNS Lookup
        t0 = time.time()
        ip = socket.gethostbyname(host)
        t1 = time.time()
        timings["dns_lookup"] = round((t1 - t0) * 1000, 2)
        
        # 2. TCP Connect
        t2 = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        t3 = time.time()
        timings["tcp_connect"] = round((t3 - t2) * 1000, 2)
        
        # 3. TLS Handshake
        connected_sock = sock
        t4 = time.time()
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            t5 = time.time()
            timings["tls_handshake"] = round((t5 - t4) * 1000, 2)
            connected_sock = ssl_sock
        else:
            timings["tls_handshake"] = 0.0
            
        # 4. TTFB (Time to First Byte)
        path = parsed.request_uri
        request_str = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberOptimusWebsiteScanner/1.0\r\nConnection: close\r\n\r\n"
        
        t6 = time.time()
        connected_sock.sendall(request_str.encode())
        
        # Receive first byte
        first_byte = connected_sock.recv(1)
        t7 = time.time()
        timings["ttfb"] = round((t7 - t6) * 1000, 2)
        
        # 5. Download Time
        t8 = time.time()
        while True:
            data = connected_sock.recv(4096)
            if not data:
                break
        t9 = time.time()
        timings["download_time"] = round((t9 - t8) * 1000, 2)
        
        connected_sock.close()
        
        # 6. Total Time
        timings["total_time"] = round(
            timings["dns_lookup"] + timings["tcp_connect"] + timings["tls_handshake"] + timings["ttfb"] + timings["download_time"],
            2
        )
    except Exception:
        # If socket measurements fail, estimate using simple values or leave as 0
        pass
        
    return timings
