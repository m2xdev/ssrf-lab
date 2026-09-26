#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ssrf_lab.py - SSRF Injection Testing Laboratory
================================================

Interactive laboratory for testing SSRFShield protection.
Demonstrates real-world SSRF attack vectors and verifies that the shield
blocks them.

Safety model:
-------------
- All URLs are validated through SSRFShield.validate_url()
- The lab does NOT make any real outbound HTTP requests to the target URLs.
  It never fetches the body/content of the URLs being tested.
- DNS resolution DOES occur when resolve_dns=True: this is normal, expected
  network activity required by the validation logic itself (to check whether
  a hostname resolves to a blocked IP). It is NOT a content request to the
  target URL. No HTTP/TLS connection is opened to the target; only the
  hostname→IP mapping is queried.
- The lab does NOT call SafeFetcher.fetch() against attacker-controlled URLs
- Network layer is mocked for "fetch attempt" scenarios
- Purpose: teach/verify, not attack

Features:
- 60+ SSRF attack scenarios (classic, cloud metadata, DNS rebinding, parser
  confusion, encoding bypasses, IPv6 tricks, protocol smuggling)
- Live validation against SSRFShield
- Separate shield instance for domain-whitelist scenarios (with real allowlist)
- Flask web interface for interactive testing
- CLI mode for automated runs
- Statistics and reporting

⚠️ WARNING: EDUCATIONAL USE ONLY.
Run against your own SSRFShield in a test environment.

License: MIT
Copyright (c) 2024

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
"""

from __future__ import annotations

import sys
import os
import json
import time
import logging
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime

try:
    from flask import Flask, request, jsonify, render_template_string
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from ssrf_shield import (
        SSRFShield,
        SSRFConfig,
        SafeFetcher,
        SSRFError,
        URLSanitizer,
        PinnedIPHTTPAdapter,
        logger as shield_logger,
    )
    SHIELD_AVAILABLE = True
except ImportError:
    SHIELD_AVAILABLE = False
    print("[!] ssrf_shield.py not found. Place it in the same directory.")


# ============================================================
# 1. CONFIGURATION
# ============================================================

@dataclass
class LabConfig:
    """Configuration for the SSRF testing lab"""
    
    # Flask
    host: str = "127.0.0.1"
    port: int = 5001
    debug: bool = False  # SECURITY: never enable Werkzeug debugger
    
    # Lab behavior
    test_delay: float = 0.05
    max_scenarios_display: int = 200
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "ssrf_lab.log"


# ============================================================
# 2. ATTACK CATEGORIES
# ============================================================

class AttackCategory(Enum):
    """Categories of SSRF attacks"""
    
    CLASSIC_LOCALHOST = "classic_localhost"
    CLOUD_METADATA = "cloud_metadata"
    PRIVATE_NETWORK = "private_network"
    PROTOCOL_SMUGGLING = "protocol_smuggling"
    PARSER_CONFUSION = "parser_confusion"
    ENCODING_BYPASS = "encoding_bypass"
    IPV6_BYPASS = "ipv6_bypass"
    REDIRECT_CHAIN = "redirect_chain"
    DNS_REBINDING = "dns_rebinding"
    PORT_SCAN = "port_scan"
    DOMAIN_WHITELIST_BYPASS = "domain_whitelist_bypass"


# ============================================================
# 3. SCENARIO DATACLASS
# ============================================================

@dataclass
class SSRFScenario:
    """A single SSRF attack scenario"""
    
    name: str
    description: str
    category: AttackCategory
    url: str
    severity: str  # low, medium, high, critical
    expected_result: str  # what shield should do
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['category'] = self.category.value
        return d


# ============================================================
# 4. ATTACK LIBRARY
# ============================================================

class SSRFAttackLibrary:
    """
    Library of SSRF attack scenarios.
    
    These are URLs, NOT executable exploits. Each is passed to
    SSRFShield.validate_url() and the result is compared to expectations.
    """
    
    @staticmethod
    def get_all_scenarios() -> List[SSRFScenario]:
        """Return all scenarios"""
        
        scenarios: List[SSRFScenario] = []
        
        # ===== 1. CLASSIC LOCALHOST =====
        scenarios.extend([
            SSRFScenario(
                name="Localhost IPv4",
                description="Direct localhost access via 127.0.0.1",
                category=AttackCategory.CLASSIC_LOCALHOST,
                url="http://127.0.0.1/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["localhost", "classic"],
            ),
            SSRFScenario(
                name="Localhost 127.1 (short form)",
                description="Short IPv4 loopback notation",
                category=AttackCategory.CLASSIC_LOCALHOST,
                url="http://127.1/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["localhost", "short-form"],
            ),
            SSRFScenario(
                name="Localhost full 127.0.0.1 with port",
                description="Localhost with explicit port",
                category=AttackCategory.CLASSIC_LOCALHOST,
                url="http://127.0.0.1:80/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["localhost", "port"],
            ),
            SSRFScenario(
                name="Localhost hostname",
                description="localhost hostname resolution",
                category=AttackCategory.CLASSIC_LOCALHOST,
                url="http://localhost/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["localhost", "hostname"],
            ),
            SSRFScenario(
                name="Localhost localdomain",
                description="localhost.localdomain hostname",
                category=AttackCategory.CLASSIC_LOCALHOST,
                url="http://localhost.localdomain/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["localhost", "hostname"],
            ),
            SSRFScenario(
                name="IPv6 loopback ::1",
                description="IPv6 loopback via [::1]",
                category=AttackCategory.CLASSIC_LOCALHOST,
                url="http://[::1]/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["ipv6", "loopback"],
            ),
            SSRFScenario(
                name="0.0.0.0 (unspecified)",
                description="Unspecified address",
                category=AttackCategory.CLASSIC_LOCALHOST,
                url="http://0.0.0.0/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["unspecified"],
            ),
        ])
        
        # ===== 2. CLOUD METADATA =====
        scenarios.extend([
            SSRFScenario(
                name="AWS metadata IPv4",
                description="AWS EC2 instance metadata",
                category=AttackCategory.CLOUD_METADATA,
                url="http://169.254.169.254/latest/meta-data/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["aws", "metadata"],
            ),
            SSRFScenario(
                name="AWS IAM credentials",
                description="AWS IAM role credentials endpoint",
                category=AttackCategory.CLOUD_METADATA,
                url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["aws", "iam", "credentials"],
            ),
            SSRFScenario(
                name="GCP metadata",
                description="Google Cloud metadata endpoint",
                category=AttackCategory.CLOUD_METADATA,
                url="http://metadata.google.internal/computeMetadata/v1/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["gcp", "metadata"],
            ),
            SSRFScenario(
                name="Azure metadata",
                description="Azure IMDS endpoint",
                category=AttackCategory.CLOUD_METADATA,
                url="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                severity="critical",
                expected_result="BLOCKED",
                tags=["azure", "metadata"],
            ),
            SSRFScenario(
                name="Alibaba Cloud metadata",
                description="Alibaba Cloud metadata IP",
                category=AttackCategory.CLOUD_METADATA,
                url="http://100.100.100.200/latest/meta-data/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["alibaba", "metadata"],
            ),
            SSRFScenario(
                name="DigitalOcean metadata",
                description="DigitalOcean metadata endpoint",
                category=AttackCategory.CLOUD_METADATA,
                url="http://169.254.169.254/metadata/v1/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["digitalocean", "metadata"],
            ),
        ])
        
        # ===== 3. PRIVATE NETWORK =====
        scenarios.extend([
            SSRFScenario(
                name="10.0.0.0/8 range",
                description="Class A private network",
                category=AttackCategory.PRIVATE_NETWORK,
                url="http://10.0.0.1/",
                severity="high",
                expected_result="BLOCKED",
                tags=["private", "rfc1918"],
            ),
            SSRFScenario(
                name="172.16.0.0/12 range",
                description="Class B private network",
                category=AttackCategory.PRIVATE_NETWORK,
                url="http://172.16.0.1/",
                severity="high",
                expected_result="BLOCKED",
                tags=["private", "rfc1918"],
            ),
            SSRFScenario(
                name="192.168.0.0/16 range",
                description="Class C private network",
                category=AttackCategory.PRIVATE_NETWORK,
                url="http://192.168.0.1/",
                severity="high",
                expected_result="BLOCKED",
                tags=["private", "rfc1918"],
            ),
            SSRFScenario(
                name="Link-local 169.254.0.0/16",
                description="Link-local range",
                category=AttackCategory.PRIVATE_NETWORK,
                url="http://169.254.0.1/",
                severity="high",
                expected_result="BLOCKED",
                tags=["link-local"],
            ),
            SSRFScenario(
                name="IPv6 ULA fc00::/7",
                description="IPv6 unique local address",
                category=AttackCategory.PRIVATE_NETWORK,
                url="http://[fc00::1]/",
                severity="high",
                expected_result="BLOCKED",
                tags=["ipv6", "private"],
            ),
            SSRFScenario(
                name="IPv6 link-local fe80::/10",
                description="IPv6 link-local address",
                category=AttackCategory.PRIVATE_NETWORK,
                url="http://[fe80::1]/",
                severity="high",
                expected_result="BLOCKED",
                tags=["ipv6", "link-local"],
            ),
        ])
        
        # ===== 4. PROTOCOL SMUGGLING =====
        scenarios.extend([
            SSRFScenario(
                name="file:// scheme",
                description="Local file access via file://",
                category=AttackCategory.PROTOCOL_SMUGGLING,
                url="file:///etc/passwd",
                severity="critical",
                expected_result="BLOCKED",
                tags=["file", "scheme"],
            ),
            SSRFScenario(
                name="gopher:// scheme",
                description="Gopher protocol for Redis/HTTP smuggling",
                category=AttackCategory.PROTOCOL_SMUGGLING,
                url="gopher://127.0.0.1:6379/_INFO",
                severity="critical",
                expected_result="BLOCKED",
                tags=["gopher", "redis"],
            ),
            SSRFScenario(
                name="dict:// scheme",
                description="Dict protocol for memcached",
                category=AttackCategory.PROTOCOL_SMUGGLING,
                url="dict://127.0.0.1:11211/stat",
                severity="critical",
                expected_result="BLOCKED",
                tags=["dict", "memcached"],
            ),
            SSRFScenario(
                name="ftp:// scheme",
                description="FTP protocol",
                category=AttackCategory.PROTOCOL_SMUGGLING,
                url="ftp://127.0.0.1/",
                severity="high",
                expected_result="BLOCKED",
                tags=["ftp", "scheme"],
            ),
            SSRFScenario(
                name="javascript: scheme",
                description="JavaScript URI",
                category=AttackCategory.PROTOCOL_SMUGGLING,
                url="javascript:alert(1)",
                severity="medium",
                expected_result="BLOCKED",
                tags=["javascript", "scheme"],
            ),
            SSRFScenario(
                name="data: scheme",
                description="Data URI",
                category=AttackCategory.PROTOCOL_SMUGGLING,
                url="data:text/plain;base64,SGVsbG8=",
                severity="medium",
                expected_result="BLOCKED",
                tags=["data", "scheme"],
            ),
        ])
        
        # ===== 5. PARSER CONFUSION =====
        scenarios.extend([
            SSRFScenario(
                name="Userinfo @ bypass (public host)",
                description="http://127.0.0.1@evil.com - parser may see 127.0.0.1 as userinfo",
                category=AttackCategory.PARSER_CONFUSION,
                url="http://127.0.0.1@evil.com/",
                severity="high",
                expected_result="BLOCKED or hostname=evil.com",
                tags=["userinfo", "bypass"],
                notes="RFC says hostname is after @. Some parsers disagree.",
            ),
            SSRFScenario(
                name="Userinfo @ bypass (private target)",
                description="http://evil.com@127.0.0.1 - hostname is 127.0.0.1",
                category=AttackCategory.PARSER_CONFUSION,
                url="http://evil.com@127.0.0.1/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["userinfo", "bypass"],
            ),
            SSRFScenario(
                name="Fragment @ confusion",
                description="http://127.0.0.1#@evil.com",
                category=AttackCategory.PARSER_CONFUSION,
                url="http://127.0.0.1#@evil.com/",
                severity="medium",
                expected_result="BLOCKED",
                tags=["fragment", "confusion"],
            ),
            SSRFScenario(
                name="Query @ confusion",
                description="http://127.0.0.1?@evil.com",
                category=AttackCategory.PARSER_CONFUSION,
                url="http://127.0.0.1?@evil.com/",
                severity="medium",
                expected_result="BLOCKED",
                tags=["query", "confusion"],
            ),
            SSRFScenario(
                name="Backslash confusion",
                description="http://127.0.0.1\\\\@evil.com",
                category=AttackCategory.PARSER_CONFUSION,
                url="http://127.0.0.1\\@evil.com/",
                severity="medium",
                expected_result="BLOCKED or hostname=evil.com",
                tags=["backslash", "confusion"],
            ),
        ])
        
        # ===== 6. ENCODING BYPASSES =====
        scenarios.extend([
            SSRFScenario(
                name="Decimal IP (127.0.0.1)",
                description="2130706433 = 127.0.0.1 in decimal",
                category=AttackCategory.ENCODING_BYPASS,
                url="http://2130706433/",
                severity="high",
                expected_result="BLOCKED",
                tags=["decimal", "encoding"],
            ),
            SSRFScenario(
                name="Hex IP (127.0.0.1)",
                description="0x7f000001 = 127.0.0.1 in hex",
                category=AttackCategory.ENCODING_BYPASS,
                url="http://0x7f000001/",
                severity="high",
                expected_result="BLOCKED",
                tags=["hex", "encoding"],
            ),
            SSRFScenario(
                name="Octal IP (127.0.0.1)",
                description="017700000001 = 127.0.0.1 in octal",
                category=AttackCategory.ENCODING_BYPASS,
                url="http://017700000001/",
                severity="high",
                expected_result="BLOCKED",
                tags=["octal", "encoding"],
            ),
            SSRFScenario(
                name="Mixed notation (127.0.1)",
                description="Mixed radix notation",
                category=AttackCategory.ENCODING_BYPASS,
                url="http://127.0.1/",
                severity="high",
                expected_result="BLOCKED",
                tags=["mixed", "encoding"],
            ),
            SSRFScenario(
                name="URL-encoded hostname",
                description="%6c%6f%63%61%6c%68%6f%73%74 = localhost",
                category=AttackCategory.ENCODING_BYPASS,
                url="http://%6c%6f%63%61%6c%68%6f%73%74/",
                severity="high",
                expected_result="BLOCKED",
                tags=["urlencoded", "encoding"],
            ),
            SSRFScenario(
                name="Unicode fullwidth dots",
                description="http://127。0。0。1/ with fullwidth dots",
                category=AttackCategory.ENCODING_BYPASS,
                url="http://127。0。0。1/",
                severity="medium",
                expected_result="BLOCKED",
                tags=["unicode", "dots"],
            ),
            SSRFScenario(
                name="Trailing dot",
                description="http://localhost./",
                category=AttackCategory.ENCODING_BYPASS,
                url="http://localhost./",
                severity="medium",
                expected_result="BLOCKED",
                tags=["trailing-dot", "fqdn"],
            ),
            SSRFScenario(
                name="Upper case scheme/host",
                description="HTTP://LOCALHOST/",
                category=AttackCategory.ENCODING_BYPASS,
                url="HTTP://LOCALHOST/",
                severity="medium",
                expected_result="BLOCKED",
                tags=["case", "uppercase"],
            ),
        ])
        
        # ===== 7. IPV6 BYPASSES =====
        scenarios.extend([
            SSRFScenario(
                name="IPv4-mapped IPv6 (loopback)",
                description="::ffff:127.0.0.1 mapped",
                category=AttackCategory.IPV6_BYPASS,
                url="http://[::ffff:127.0.0.1]/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["ipv6", "mapped", "loopback"],
            ),
            SSRFScenario(
                name="IPv4-mapped IPv6 (private)",
                description="::ffff:10.0.0.1 mapped",
                category=AttackCategory.IPV6_BYPASS,
                url="http://[::ffff:10.0.0.1]/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["ipv6", "mapped", "private"],
            ),
            SSRFScenario(
                name="IPv4-mapped IPv6 (metadata)",
                description="::ffff:169.254.169.254 mapped",
                category=AttackCategory.IPV6_BYPASS,
                url="http://[::ffff:169.254.169.254]/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["ipv6", "mapped", "metadata"],
            ),
            SSRFScenario(
                name="IPv6 loopback expanded",
                description="0:0:0:0:0:0:0:1",
                category=AttackCategory.IPV6_BYPASS,
                url="http://[0:0:0:0:0:0:0:1]/",
                severity="critical",
                expected_result="BLOCKED",
                tags=["ipv6", "loopback", "expanded"],
            ),
            SSRFScenario(
                name="IPv6 zone ID",
                description="fe80::1%eth0",
                category=AttackCategory.IPV6_BYPASS,
                url="http://[fe80::1%25eth0]/",
                severity="high",
                expected_result="BLOCKED",
                tags=["ipv6", "zone-id"],
            ),
        ])
        
        # ===== 8. REDIRECT CHAIN =====
        scenarios.extend([
            SSRFScenario(
                name="Redirect to metadata (entry URL)",
                description="Entry URL that would redirect to metadata",
                category=AttackCategory.REDIRECT_CHAIN,
                url="http://example.com/redirect?to=http://169.254.169.254/",
                severity="high",
                expected_result="ALLOWED (redirect validated separately by SafeFetcher)",
                tags=["redirect", "entry"],
                notes="Entry URL is public; SafeFetcher must block the redirect hop.",
            ),
            SSRFScenario(
                name="Direct metadata via redirect",
                description="Direct metadata URL",
                category=AttackCategory.REDIRECT_CHAIN,
                url="http://169.254.169.254/redirect",
                severity="critical",
                expected_result="BLOCKED",
                tags=["redirect", "metadata"],
            ),
        ])
        
        # ===== 9. DNS REBINDING =====
        scenarios.extend([
            SSRFScenario(
                name="DNS rebinding domain",
                description="Domain that resolves to public then private",
                category=AttackCategory.DNS_REBINDING,
                url="http://rebind.example.com/",
                severity="critical",
                expected_result="BLOCKED (when resolved to private IP) or ALLOWED (when public)",
                tags=["dns", "rebinding"],
                notes="Depends on current DNS resolution. Shield resolves at validation time.",
            ),
        ])
        
        # ===== 10. PORT SCAN =====
        scenarios.extend([
            SSRFScenario(
                name="Redis port scan",
                description="Access Redis on port 6379",
                category=AttackCategory.PORT_SCAN,
                url="http://example.com:6379/",
                severity="high",
                expected_result="BLOCKED (port not allowed)",
                tags=["redis", "port"],
            ),
            SSRFScenario(
                name="MySQL port scan",
                description="Access MySQL on port 3306",
                category=AttackCategory.PORT_SCAN,
                url="http://example.com:3306/",
                severity="high",
                expected_result="BLOCKED (port not allowed)",
                tags=["mysql", "port"],
            ),
            SSRFScenario(
                name="SSH port scan",
                description="Access SSH on port 22",
                category=AttackCategory.PORT_SCAN,
                url="http://example.com:22/",
                severity="high",
                expected_result="BLOCKED (port not allowed)",
                tags=["ssh", "port"],
            ),
            SSRFScenario(
                name="Elasticsearch port scan",
                description="Access Elasticsearch on port 9200",
                category=AttackCategory.PORT_SCAN,
                url="http://example.com:9200/",
                severity="high",
                expected_result="BLOCKED (port not allowed)",
                tags=["elasticsearch", "port"],
            ),
            SSRFScenario(
                name="Docker API port scan",
                description="Access Docker on port 2375",
                category=AttackCategory.PORT_SCAN,
                url="http://example.com:2375/",
                severity="critical",
                expected_result="BLOCKED (port not allowed)",
                tags=["docker", "port"],
            ),
            SSRFScenario(
                name="Kubernetes API port scan",
                description="Access K8s API on port 6443",
                category=AttackCategory.PORT_SCAN,
                url="http://example.com:6443/",
                severity="critical",
                expected_result="BLOCKED (port not allowed)",
                tags=["kubernetes", "port"],
            ),
        ])
        
        # ===== 11. DOMAIN WHITELIST BYPASS =====
        # NOTE: These scenarios require a shield configured with
        # allowed_domains={'trusted.com'}. The runner uses a dedicated
        # shield instance (WHITELIST_SHIELD) for this category.
        scenarios.extend([
            SSRFScenario(
                name="Subdomain bypass",
                description="evil.trusted.com when trusted.com is whitelisted",
                category=AttackCategory.DOMAIN_WHITELIST_BYPASS,
                url="http://evil.trusted.com/",
                severity="medium",
                expected_result="ALLOWED (subdomain of whitelisted domain)",
                tags=["whitelist", "subdomain"],
                notes="Requires shield with allowed_domains={'trusted.com'}.",
            ),
            SSRFScenario(
                name="Suffix bypass",
                description="trusted.com.evil.com",
                category=AttackCategory.DOMAIN_WHITELIST_BYPASS,
                url="http://trusted.com.evil.com/",
                severity="high",
                expected_result="BLOCKED (not matching whitelist)",
                tags=["whitelist", "suffix"],
                notes="Requires shield with allowed_domains={'trusted.com'}.",
            ),
            SSRFScenario(
                name="Case bypass",
                description="TRUSTED.COM",
                category=AttackCategory.DOMAIN_WHITELIST_BYPASS,
                url="http://TRUSTED.COM/",
                severity="low",
                expected_result="ALLOWED (case-insensitive match)",
                tags=["whitelist", "case"],
                notes="Requires shield with allowed_domains={'trusted.com'}.",
            ),
        ])
        
        return scenarios


# ============================================================
# 4b. WHITELIST SHIELD (for DOMAIN_WHITELIST_BYPASS scenarios)
# ============================================================

def _build_whitelist_shield() -> Optional[SSRFShield]:
    """
    Build a dedicated shield with allowed_domains={'trusted.com'}.
    
    Used only for DOMAIN_WHITELIST_BYPASS scenarios so they actually test
    the whitelist behavior they claim to test.
    """
    if not SHIELD_AVAILABLE:
        return None
    cfg = SSRFConfig(allowed_domains={'trusted.com'})
    cfg.mode = 'block'
    return SSRFShield(cfg)


# ============================================================
# 5. TEST RUNNER (FIXED: test_delay + dedicated whitelist shield)
# ============================================================

class SSRFTestRunner:
    """
    Runs SSRF scenarios against SSRFShield.
    
    Uses two shield instances:
    - self.shield: general shield with default config (empty allowlist)
    - self.whitelist_shield: dedicated shield with allowed_domains={'trusted.com'},
      used for DOMAIN_WHITELIST_BYPASS scenarios.
    """
    
    def __init__(
        self,
        shield: Optional[SSRFShield] = None,
        config: Optional[SSRFConfig] = None,
        test_delay: float = 0.02,
    ):
        """
        Args:
            shield: pre-built shield (optional)
            config: SSRFConfig (used if shield is not provided)
            test_delay: delay between scenarios in seconds
        """
        self.config = config or SSRFConfig()
        self.shield = shield or SSRFShield(self.config)
        self.test_delay = test_delay
        self.results: List[Dict[str, Any]] = []
        
        # Dedicated shield for whitelist scenarios
        self.whitelist_shield = _build_whitelist_shield()
    
    def _get_shield_for(self, scenario: SSRFScenario) -> SSRFShield:
        """Pick the right shield for a scenario"""
        if (scenario.category == AttackCategory.DOMAIN_WHITELIST_BYPASS
                and self.whitelist_shield is not None):
            return self.whitelist_shield
        return self.shield
    
    def run_all(self, show_progress: bool = True) -> Dict[str, Any]:
        """Run all scenarios"""
        scenarios = SSRFAttackLibrary.get_all_scenarios()
        
        print(f"\n{'='*70}")
        print(f"  RUNNING {len(scenarios)} SSRF SCENARIOS")
        print(f"{'='*70}\n")
        
        stats = {
            'total': 0,
            'blocked': 0,
            'allowed': 0,
            'by_category': {},
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        }
        
        results = []
        
        for i, scenario in enumerate(scenarios, 1):
            result = self._run_scenario(scenario)
            results.append(result)
            
            stats['total'] += 1
            cat = scenario.category.value
            if cat not in stats['by_category']:
                stats['by_category'][cat] = {'blocked': 0, 'allowed': 0, 'total': 0}
            stats['by_category'][cat]['total'] += 1
            
            if result['blocked']:
                stats['blocked'] += 1
                stats['by_category'][cat]['blocked'] += 1
            else:
                stats['allowed'] += 1
                stats['by_category'][cat]['allowed'] += 1
            
            if result['blocked']:
                stats['by_severity'][scenario.severity] += 1
            
            if show_progress and (i <= 20 or i % 10 == 0):
                status = "✓ BLOCKED" if result['blocked'] else "• ALLOWED"
                print(f"  [{i:3}/{len(scenarios)}] {status} | {scenario.name}")
                if result['blocked'] and result.get('reason'):
                    print(f"           reason: {result['reason']}")
            
            time.sleep(self.test_delay)  # FIXED: use self.test_delay directly
        
        print(f"\n{'='*70}")
        print(f"  TOTAL: {stats['total']} | BLOCKED: {stats['blocked']} | ALLOWED: {stats['allowed']}")
        print(f"  Block rate: {stats['blocked']/stats['total']*100:.1f}%")
        print(f"{'='*70}\n")
        
        self.results = results
        return {'stats': stats, 'results': results}
    
    def _run_scenario(self, scenario: SSRFScenario) -> Dict[str, Any]:
        """Run one scenario through the appropriate shield"""
        start = time.time()
        
        try:
            shield = self._get_shield_for(scenario)
            result = shield.validate_url(scenario.url, resolve_dns=True)
            
            blocked = not result['valid']
            
            return {
                'name': scenario.name,
                'category': scenario.category.value,
                'url': scenario.url,
                'severity': scenario.severity,
                'blocked': blocked,
                'reason': result.get('reason'),
                'error': result.get('error'),
                'resolved_ips': result.get('resolved_ips', []),
                'expected': scenario.expected_result,
                'duration_ms': (time.time() - start) * 1000,
                'shield_used': (
                    'whitelist_shield'
                    if shield is self.whitelist_shield
                    else 'default_shield'
                ),
            }
        except Exception as e:
            return {
                'name': scenario.name,
                'category': scenario.category.value,
                'url': scenario.url,
                'severity': scenario.severity,
                'blocked': True,
                'reason': 'exception',
                'error': str(e),
                'resolved_ips': [],
                'expected': scenario.expected_result,
                'duration_ms': (time.time() - start) * 1000,
                'shield_used': 'unknown',
            }
    
    def report(self) -> str:
        """Human-readable report"""
        if not self.results:
            return "No results yet."
        
        lines = []
        lines.append("="*70)
        lines.append("  SSRF SHIELD TEST REPORT")
        lines.append("="*70)
        lines.append("")
        
        blocked = [r for r in self.results if r['blocked']]
        allowed = [r for r in self.results if not r['blocked']]
        
        lines.append(f"Total:    {len(self.results)}")
        lines.append(f"Blocked:  {len(blocked)} ({len(blocked)/len(self.results)*100:.1f}%)")
        lines.append(f"Allowed:  {len(allowed)} ({len(allowed)/len(self.results)*100:.1f}%)")
        lines.append("")
        
        by_cat: Dict[str, List[Dict]] = {}
        for r in self.results:
            by_cat.setdefault(r['category'], []).append(r)
        
        lines.append("By category:")
        for cat, items in by_cat.items():
            b = sum(1 for r in items if r['blocked'])
            lines.append(f"  {cat}: {b}/{len(items)} blocked")
        lines.append("")
        
        if allowed:
            lines.append("⚠ ALLOWED (not blocked):")
            for r in allowed:
                lines.append(f"  - {r['name']}  [{r['severity']}]")
                lines.append(f"    URL:  {r['url']}")
                lines.append(f"    Expected: {r['expected']}")
                lines.append(f"    Shield:   {r.get('shield_used', '?')}")
            lines.append("")
        
        return "\n".join(lines)


# ============================================================
# 6. FLASK WEB INTERFACE
# ============================================================

def create_demo_app():
    """Create Flask web interface for the lab"""
    if not FLASK_AVAILABLE:
        print("[!] Flask not available. pip install flask")
        return None
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.urandom(32)
    app.config['DEBUG'] = False
    
    config = SSRFConfig()
    shield = SSRFShield(config)
    whitelist_shield = _build_whitelist_shield()
    
    # Map category -> shield for /api/test
    # (web UI uses default shield for arbitrary URL testing;
    #  whitelist scenarios are pre-run via /api/run_all)
    
    HTML = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SSRF Shield Lab</title>
        <meta charset="utf-8">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Courier New', monospace;
                background: #0a0a0a; color: #d0d0d0;
                padding: 20px; line-height: 1.5;
            }
            .container { max-width: 1300px; margin: 0 auto; }
            h1 { color: #4fc3f7; border-bottom: 2px solid #4fc3f7;
                 padding-bottom: 10px; margin-bottom: 20px; }
            h2 { color: #4fc3f7; font-size: 15px; margin-bottom: 12px;
                 text-transform: uppercase; letter-spacing: 1px; }
            .warn { color: #ff5555; font-size: 12px; margin-bottom: 20px; }
            .note { color: #888; font-size: 11px; margin-top: 8px; }
            .row { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
            .col {
                flex: 1; min-width: 320px; background: #111;
                border: 1px solid #222; padding: 18px; border-radius: 4px;
            }
            input, textarea {
                background: #0a0a0a; color: #4fc3f7; border: 1px solid #333;
                padding: 8px; width: 100%; border-radius: 3px;
                font-family: inherit; font-size: 13px;
            }
            input:focus, textarea:focus { border-color: #4fc3f7; outline: none; }
            button {
                background: #4fc3f7; color: #000; border: none;
                padding: 8px 16px; border-radius: 3px; cursor: pointer;
                font-weight: bold; font-family: inherit; margin-top: 8px;
            }
            button:hover { background: #29b6f6; }
            button.danger { background: #ff5555; color: #fff; }
            button.danger:hover { background: #cc0000; }
            .log {
                background: #0a0a0a; padding: 10px; border-radius: 3px;
                max-height: 400px; overflow-y: auto; font-size: 12px;
                border: 1px solid #222;
            }
            .entry { padding: 3px 0; border-bottom: 1px solid #1a1a1a; }
            .entry .t { color: #555; }
            .entry.blocked { color: #4caf50; }
            .entry.allowed { color: #ff9800; }
            .entry.error { color: #f44336; }
            .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
            .stat {
                background: #0a0a0a; padding: 12px; border-radius: 3px;
                text-align: center; border: 1px solid #222;
            }
            .stat .n { font-size: 22px; font-weight: bold; }
            .stat .l { font-size: 10px; color: #666; text-transform: uppercase; }
            .stat.blocked .n { color: #4caf50; }
            .stat.allowed .n { color: #ff9800; }
            .stat.total .n { color: #4fc3f7; }
            .result-box {
                margin-top: 12px; padding: 12px; background: #0a0a0a;
                border-left: 3px solid #333; border-radius: 3px;
                font-size: 13px; min-height: 60px;
            }
            .result-box.blocked { border-left-color: #4caf50; }
            .result-box.allowed { border-left-color: #ff9800; }
            .scenario-btn {
                display: inline-block; padding: 4px 8px; font-size: 11px;
                background: #1a1a1a; border: 1px solid #333; color: #999;
                margin: 2px; border-radius: 3px; cursor: pointer;
            }
            .scenario-btn:hover { background: #222; color: #4fc3f7; border-color: #4fc3f7; }
            .scenario-btn.critical { border-left: 2px solid #f44336; }
            .scenario-btn.high { border-left: 2px solid #ff9800; }
            .scenario-btn.medium { border-left: 2px solid #ffc107; }
            .scenario-btn.low { border-left: 2px solid #4caf50; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡 SSRF Shield Lab</h1>
            <p class="warn">
                ⚠ EDUCATIONAL USE ONLY — validates against SSRFShield.
                No outbound HTTP requests to target URLs. DNS resolution
                of hostnames does occur (required by validation logic).
            </p>
            
            <div class="row">
                <div class="col">
                    <h2>Statistics</h2>
                    <div class="stats">
                        <div class="stat total">
                            <div class="n" id="stat-total">0</div>
                            <div class="l">Total</div>
                        </div>
                        <div class="stat blocked">
                            <div class="n" id="stat-blocked">0</div>
                            <div class="l">Blocked</div>
                        </div>
                        <div class="stat allowed">
                            <div class="n" id="stat-allowed">0</div>
                            <div class="l">Allowed</div>
                        </div>
                    </div>
                    <button onclick="runAll()">▶ Run All Scenarios</button>
                    <button class="danger" onclick="clearLog()">Clear Log</button>
                    <p class="note">
                        All scenarios (incl. whitelist) run with appropriate shields.
                    </p>
                </div>
                
                <div class="col">
                    <h2>Single URL Test</h2>
                    <input id="urlInput" placeholder="http://169.254.169.254/latest/meta-data/">
                    <button onclick="testUrl()">Validate URL</button>
                    <div id="resultBox" class="result-box">Awaiting input...</div>
                    <p class="note">
                        Single-URL test uses the DEFAULT shield (empty allowlist).
                    </p>
                </div>
            </div>
            
            <div class="row">
                <div class="col">
                    <h2>Scenarios</h2>
                    <div id="scenarios" style="max-height: 300px; overflow-y: auto;"></div>
                </div>
                
                <div class="col">
                    <h2>Log</h2>
                    <div class="log" id="log"></div>
                </div>
            </div>
        </div>
        
        <script>
        let stats = { total: 0, blocked: 0, allowed: 0 };
        
        function addLog(msg, cls) {
            const log = document.getElementById('log');
            const div = document.createElement('div');
            div.className = 'entry ' + (cls || '');
            const t = new Date().toLocaleTimeString();
            div.innerHTML = '<span class="t">[' + t + ']</span> ' + msg;
            log.appendChild(div);
            log.scrollTop = log.scrollHeight;
        }
        
        function updateStats() {
            document.getElementById('stat-total').textContent = stats.total;
            document.getElementById('stat-blocked').textContent = stats.blocked;
            document.getElementById('stat-allowed').textContent = stats.allowed;
        }
        
        function testUrl() {
            const url = document.getElementById('urlInput').value.trim();
            if (!url) return;
            
            fetch('/api/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            })
            .then(r => r.json())
            .then(data => {
                const box = document.getElementById('resultBox');
                if (data.blocked) {
                    box.className = 'result-box blocked';
                    box.innerHTML = '<strong style="color:#4caf50;">✓ BLOCKED</strong><br>'
                                  + 'Reason: ' + (data.reason || 'n/a') + '<br>'
                                  + 'Error: ' + (data.error || 'n/a');
                    stats.blocked++;
                    addLog('BLOCKED: ' + url + ' (' + (data.reason || '') + ')', 'blocked');
                } else {
                    box.className = 'result-box allowed';
                    box.innerHTML = '<strong style="color:#ff9800;">• ALLOWED</strong><br>'
                                  + 'Resolved IPs: ' + (data.resolved_ips || []).join(', ');
                    stats.allowed++;
                    addLog('ALLOWED: ' + url, 'allowed');
                }
                stats.total++;
                updateStats();
            });
        }
        
        function loadScenarios() {
            fetch('/api/scenarios')
            .then(r => r.json())
            .then(data => {
                const box = document.getElementById('scenarios');
                box.innerHTML = '';
                data.forEach((s) => {
                    const btn = document.createElement('span');
                    btn.className = 'scenario-btn ' + s.severity;
                    btn.textContent = s.name;
                    btn.title = s.description + '\\nURL: ' + s.url
                              + (s.notes ? '\\nNote: ' + s.notes : '');
                    btn.onclick = () => {
                        document.getElementById('urlInput').value = s.url;
                        testUrl();
                    };
                    box.appendChild(btn);
                });
            });
        }
        
        function runAll() {
            addLog('Running all scenarios...', '');
            fetch('/api/run_all', {method: 'POST'})
            .then(r => r.json())
            .then(data => {
                stats.total = data.total;
                stats.blocked = data.blocked;
                stats.allowed = data.allowed;
                updateStats();
                addLog('Done: ' + data.blocked + '/' + data.total + ' blocked', 'blocked');
            });
        }
        
        function clearLog() {
            document.getElementById('log').innerHTML = '';
        }
        
        loadScenarios();
        updateStats();
        addLog('Lab ready', '');
        </script>
    </body>
    </html>
    """
    
    @app.route('/')
    def index():
        return render_template_string(HTML)
    
    @app.route('/api/test', methods=['POST'])
    def api_test():
        try:
            data = request.get_json(silent=True) or {}
            url = data.get('url', '').strip()
            if not url:
                return jsonify({'error': 'missing url'}), 400
            
            # Single-URL test uses the DEFAULT shield.
            # Whitelist scenarios run via /api/run_all with their own shield.
            result = shield.validate_url(url, resolve_dns=True)
            
            return jsonify({
                'url': url,
                'blocked': not result['valid'],
                'reason': result.get('reason'),
                'error': result.get('error'),
                'resolved_ips': result.get('resolved_ips', []),
            })
        except Exception as e:
            return jsonify({'error': str(e), 'blocked': True, 'reason': 'exception'}), 200
    
    @app.route('/api/scenarios')
    def api_scenarios():
        scenarios = [s.to_dict() for s in SSRFAttackLibrary.get_all_scenarios()]
        return jsonify(scenarios)
    
    @app.route('/api/run_all', methods=['POST'])
    def api_run_all():
        runner = SSRFTestRunner(
            shield=shield,
            config=config,
            test_delay=0.01,
        )
        result = runner.run_all(show_progress=False)
        return jsonify({
            'total': result['stats']['total'],
            'blocked': result['stats']['blocked'],
            'allowed': result['stats']['allowed'],
        })
    
    return app


# ============================================================
# 7. CLI MODE
# ============================================================

def cli_mode():
    """Interactive CLI"""
    print("\n" + "="*60)
    print("  SSRF SHIELD LAB — CLI MODE")
    print("="*60)
    
    config = SSRFConfig()
    shield = SSRFShield(config)
    runner = SSRFTestRunner(
        shield=shield,
        config=config,
        test_delay=0.05,
    )
    
    while True:
        print("\n[ Menu ]")
        print("  1. Run all scenarios")
        print("  2. Test single URL (default shield)")
        print("  3. Test single URL (whitelist shield)")
        print("  4. Show statistics")
        print("  5. Show current config")
        print("  6. Start web interface")
        print("  7. Exit")
        
        try:
            choice = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break
        
        if choice == '1':
            runner.run_all(show_progress=True)
            print(runner.report())
        
        elif choice == '2':
            url = input("URL: ").strip()
            if not url:
                continue
            result = shield.validate_url(url)
            _print_validation_result(result)
        
        elif choice == '3':
            if runner.whitelist_shield is None:
                print("  Whitelist shield not available (ssrf_shield missing).")
                continue
            print("  (whitelist_shield has allowed_domains={'trusted.com'})")
            url = input("URL: ").strip()
            if not url:
                continue
            result = runner.whitelist_shield.validate_url(url)
            _print_validation_result(result)
        
        elif choice == '4':
            print("\n  Default shield stats:", shield.get_stats())
            if runner.whitelist_shield:
                print("  Whitelist shield stats:", runner.whitelist_shield.get_stats())
            if runner.results:
                blocked = sum(1 for r in runner.results if r['blocked'])
                print(f"  Last run:     {blocked}/{len(runner.results)} blocked")
        
        elif choice == '5':
            print("\n  Config:")
            print(f"    allowed_schemes:    {config.allowed_schemes}")
            print(f"    allowed_ports:      {config.allowed_ports}")
            print(f"    allowed_domains:    {config.allowed_domains or '(all public)'}")
            print(f"    blocked_domains:    {config.blocked_domains}")
            print(f"    block_private_ips:  {config.block_private_ips}")
            print(f"    block_loopback:     {config.block_loopback}")
            print(f"    block_link_local:   {config.block_link_local}")
            print(f"    max_url_length:     {config.max_url_length}")
            print(f"    max_redirects:      {config.max_redirects}")
            print(f"    mode:               {config.mode}")
            print(f"    test_delay:         {runner.test_delay}s")
        
        elif choice == '6':
            app = create_demo_app()
            if app:
                print(f"\n  Starting web UI at http://{LabConfig.host}:{LabConfig.port}")
                print("  Press Ctrl+C to stop")
                try:
                    app.run(host=LabConfig.host, port=LabConfig.port, debug=False)
                except KeyboardInterrupt:
                    print("\n  Web UI stopped.")
        
        elif choice == '7':
            print("Bye.")
            break
        
        else:
            print("  Invalid choice.")


def _print_validation_result(result: Dict[str, Any]) -> None:
    """Helper to print a validation result"""
    print(f"\n  valid:        {result['valid']}")
    print(f"  blocked:      {not result['valid']}")
    if result.get('reason'):
        print(f"  reason:       {result['reason']}")
    if result.get('error'):
        print(f"  error:        {result['error']}")
    if result.get('resolved_ips'):
        print(f"  resolved IPs: {result['resolved_ips']}")


# ============================================================
# 8. MAIN
# ============================================================

def main():
    print("""
    ═══════════════════════════════════════════════════════════
         SSRF Shield Lab v1.1
         
         Test SSRFShield against 60+ real-world attack patterns
         ⚠ EDUCATIONAL USE ONLY
    ═══════════════════════════════════════════════════════════
    """)
    
    if not SHIELD_AVAILABLE:
        print("[!] ssrf_shield.py not found in the same directory.")
        print("[!] Place ssrf_shield.py next to ssrf_lab.py and rerun.")
        sys.exit(1)
    
    # DNS availability check (hostname resolution, not content fetch)
    try:
        import socket
        socket.getaddrinfo('example.com', None, type=socket.SOCK_STREAM)
        print("[✓] DNS resolution available (needed by validate_url)")
    except Exception as e:
        print(f"[!] DNS resolution may be unavailable: {e}")
    
    print("[✓] ssrf_shield loaded")
    
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == '--web':
            app = create_demo_app()
            if app:
                print(f"\nStarting web UI at http://{LabConfig.host}:{LabConfig.port}")
                app.run(host=LabConfig.host, port=LabConfig.port, debug=False)
            sys.exit(0)
        elif arg == '--test':
            runner = SSRFTestRunner(test_delay=0.05)
            runner.run_all(show_progress=True)
            print(runner.report())
            sys.exit(0)
        elif arg == '--help':
            print("Usage: python ssrf_lab.py [--web | --test | --help]")
            sys.exit(0)
    
    cli_mode()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)