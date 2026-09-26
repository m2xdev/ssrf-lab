# ssrf-lab

Interactive testing laboratory for [ssrf-shield](https://github.com/m2xdev/ssrf-shield) —
60+ real-world SSRF attack scenarios (classic localhost, cloud metadata,
DNS rebinding, parser confusion, encoding bypasses, IPv6 tricks, protocol
smuggling, port scanning, domain whitelist bypass) with a live web UI and
CLI, verified against the shield.

## Safety model

- All URLs are validated through `SSRFShield.validate_url()` only.
- The lab makes **no outbound HTTP/TLS requests to the scenario URLs** —
  it never fetches their content.
- DNS resolution of hostnames **does occur** (`resolve_dns=True`) — this
  is normal, expected activity required by the validation logic itself
  (checking whether a hostname resolves to a blocked IP). It is not a
  content request to the target.
- `SafeFetcher.fetch()` is never called against scenario/attacker-controlled
  URLs.
- `debug=False` is hardcoded everywhere the lab starts a Flask server.

## Installation

```bash
git clone https://github.com/m2xdev/ssrf-lab
cd ssrf-lab
pip install -r requirements.txt
```

You need `ssrf_shield.py` in the same directory (copy it from
[ssrf-shield](https://github.com/m2xdev/ssrf-shield)).

## Usage

```bash
# Interactive CLI
python ssrf_lab.py

# Web interface (http://127.0.0.1:5001)
python ssrf_lab.py --web

# Run all 60+ scenarios and print a report
python ssrf_lab.py --test
```

### CLI menu

1. Run all scenarios
2. Test a single URL against the default shield (empty allowlist)
3. Test a single URL against the whitelist shield (`allowed_domains={'trusted.com'}`)
4. Show statistics
5. Show current shield config
6. Start the web interface

## Two shield instances

The lab uses two `SSRFShield` instances so the whitelist-bypass scenarios
actually test what they claim to:

- **Default shield** — empty `allowed_domains` (all public domains allowed
  by default). Used for most scenarios and for single-URL testing in the
  web UI.
- **Whitelist shield** — configured with `allowed_domains={'trusted.com'}`.
  Used only for `DOMAIN_WHITELIST_BYPASS` scenarios (subdomain bypass,
  suffix bypass, case-insensitivity).

## Attack categories

`classic_localhost`, `cloud_metadata`, `private_network`,
`protocol_smuggling`, `parser_confusion`, `encoding_bypass`,
`ipv6_bypass`, `redirect_chain`, `dns_rebinding`, `port_scan`,
`domain_whitelist_bypass`.

Example `--test` output:

```
RUNNING 62 SSRF SCENARIOS

  [  1/62] ✓ BLOCKED | Localhost IPv4
  [  2/62] ✓ BLOCKED | Localhost 127.1 (short form)
  ...

TOTAL: 62 | BLOCKED: 58 | ALLOWED: 4
Block rate: 93.5%
```

Scenarios reported as `ALLOWED` with `expected_result="ALLOWED (...)"` are
expected (e.g. legitimate subdomain matches, entry URLs meant to be
validated at the redirect hop by `SafeFetcher` rather than here) — check
the report's reasoning against each scenario's `expected_result` before
treating an "allowed" result as a regression.

## ⚠️ Disclaimer

This repository is intended solely for education and for testing the
`ssrf-shield` defensive module in a controlled, isolated environment.

- All attack "execution" is limited to URL validation and DNS hostname
  resolution — no content is ever fetched from the scenario URLs.
- Run the web interface (`--web`) locally only.
- Do not use this code as a base for tools that make real requests to
  systems you don't own or don't have explicit authorization to test.

The software is provided **"AS IS"**, without warranty of any kind,
express or implied. By using this code, you are solely responsible for
its use. The author is not liable for any damages arising from the use
of this software.

## Related projects

- [ssrf-shield](https://github.com/m2xdev/ssrf-shield) — the defense library itself
- [nosql-shield](https://github.com/m2xdev/nosql-shield) / [nosql-lab](https://github.com/m2xdev/nosql-lab)
- [query-sql](https://github.com/m2xdev/query-sql) / [query-lab](https://github.com/m2xdev/query-lab)
- [xss-shield](https://github.com/m2xdev/xss-shield) / [xss-lab](https://github.com/m2xdev/xss-lab)
- [csrf-shield](https://github.com/m2xdev/csrf-shield) / [csrf-lab](https://github.com/m2xdev/csrf-lab)
- [stored-xss-local-tester](https://github.com/m2xdev/stored-xss-local-tester)