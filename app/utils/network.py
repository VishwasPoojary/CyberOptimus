import socket
import requests
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

def fetch_url(url: str, timeout: int = 5) -> Tuple[Optional[requests.Response], Optional[Exception]]:
    """Fetches a URL bypassing TLS validation, returning the response or exception."""
    try:
        # We explicitly set verify=False to decouple the HTTP stage from TLS validation.
        # This ensures we can still evaluate HTTP headers and status codes even on invalid certs.
        response = requests.get(url, timeout=timeout, verify=False)
        return response, None
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
        "error": None
    }
    
    # Context 1: Bypass validation to extract certificate metadata
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                result["tls_version"] = ssock.version()
                
                # Parse with cryptography
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                # Extract Issuer
                try:
                    issuer_attributes = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    if not issuer_attributes:
                        issuer_attributes = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                    if issuer_attributes:
                        result["issuer"] = issuer_attributes[0].value
                except Exception:
                    pass
                    
                # Extract Subject
                try:
                    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    o = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                    parts = []
                    if cn: parts.append(f"CN={cn[0].value}")
                    if o: parts.append(f"O={o[0].value}")
                    result["subject"] = ", ".join(parts) if parts else "Unknown"
                except Exception:
                    pass
                    
                # Extract Expiration & Days Remaining
                not_after = cert.not_valid_after_utc
                if not_after:
                    result["expiration"] = not_after.strftime("%Y-%m-%d")
                    now_utc = datetime.datetime.now(datetime.timezone.utc)
                    days_left = (not_after - now_utc).days
                    result["days_remaining"] = max(0, days_left)
                    
                # Extract SAN
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san_domains = san_ext.value.get_values_for_type(x509.DNSName)
                    result["san"] = san_domains
                except Exception:
                    pass
                    
    except Exception as e:
        result["error"] = f"Connection failed: {str(e)}"
        return result
        
    # Context 2: Standard validation to capture exact verification errors
    verify_context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with verify_context.wrap_socket(sock, server_hostname=domain) as ssock:
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
        result["error"] = str(e)
        
    return result
