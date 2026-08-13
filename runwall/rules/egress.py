"""Network egress: destination gating and proxy-evasion detection.

Scope discipline first, because this is the layer most likely to be oversold.
Runwall inspects the *tool call*, not the packet. It sees the destination an
agent asks for. It does not see traffic from a process it did not mediate, and
it does not decrypt TLS -- installing a local CA whose private key the agent can
read would trade a real secret for the appearance of visibility.

So this pack does two things well and claims nothing more:

  * gate destinations that appear in mediated calls, against an allow/deny list
  * treat *evidence of proxy evasion* as its own finding

The second matters more than it first appears. Runwall cannot stop a child
process spawned with a cleared environment from reaching the network. But an
agent that explicitly disables proxying, pins ``--noproxy``, sets
``trust_env=False`` or clears ``HTTPS_PROXY`` has told us what it is doing, and
that intent is worth refusing even when the mechanism would have worked.
"""
from __future__ import annotations

import re

from . import Finding, register

_URL = re.compile(r"(?:https?://|wss?://)([a-z0-9.\-]+(?::\d+)?)", re.IGNORECASE)
_BARE_HOST = re.compile(
    r"(?:--url|-H\s+host:|host:\s*|nc\s+|telnet\s+|ssh\s+\S+@)([a-z0-9.\-]+\.[a-z]{2,})",
    re.IGNORECASE)

_PROXY_EVASION = [
    (r"--noproxy\b", "curl --noproxy"),
    (r"\bno_proxy\s*=\s*[*\"']", "NO_PROXY wildcard"),
    (r"trust_env\s*=\s*false", "requests trust_env=False"),
    (r"proxy\s*[:=]\s*(none|null|false)", "explicit proxy disable"),
    (r"(set|export|\$env:)\s*https?_proxy\s*=\s*(''|\"\"|\s*$)", "clearing proxy env"),
    (r"unset\s+https?_proxy", "unsetting proxy env"),
    (r"env\s+-i\b", "env -i (cleared environment for a child process)"),
    (r"--insecure\b|(?<!\w)-k(?!\w)", "TLS verification disabled"),
    (r"rejectunauthorized\s*:\s*false", "TLS verification disabled"),
    (r"node_tls_reject_unauthorized\s*=\s*0", "TLS verification disabled"),
]
_PROXY_EVASION = [(re.compile(p, re.IGNORECASE), why) for p, why in _PROXY_EVASION]

# Encoding data into DNS labels is a classic covert channel and is never
# something an agent needs to do deliberately.
_DNS_EXFIL = re.compile(
    r"(nslookup|dig|resolve-dnsname|host)\s+[a-z0-9+/=_-]{28,}\.", re.IGNORECASE)
_DOH = re.compile(
    r"(dns-query|application/dns-message|1\.1\.1\.1/dns|dns\.google/resolve)",
    re.IGNORECASE)
_RAW_SOCKET = re.compile(
    r"(socket\.socket|new\s+net\.socket|nc\s+-l|ncat|/dev/tcp/)", re.IGNORECASE)
_TUNNEL = re.compile(
    r"(ngrok|cloudflared|localtunnel|serveo|localhost\.run|bore\.pub|"
    r"ssh\s+-R\s|\bsocat\b)", re.IGNORECASE)


def _hosts(text: str) -> list[str]:
    out: list[str] = []
    for m in list(_URL.finditer(text)) + list(_BARE_HOST.finditer(text)):
        host = m.group(1).split(":")[0].casefold().rstrip(".")
        if host and host not in out:
            out.append(host)
    return out


def _matches_domain(host: str, rule: str) -> bool:
    rule = rule.casefold().lstrip("*.")
    return host == rule or host.endswith("." + rule)


@register("egress")
def destination_gating(env, policy, session) -> list[Finding]:
    hosts = _hosts(env.normalized_action)
    if not hosts:
        return []

    allow = policy.egress.get("allow_domains") or []
    deny = policy.egress.get("deny_domains") or []
    out: list[Finding] = []

    for host in hosts:
        if any(_matches_domain(host, d) for d in deny):
            out.append(Finding(
                ruleId="egress.blocked_domain",
                severity="critical",
                score=100,
                message=f"destination '{host}' is on the egress denylist "
                        f"(ephemeral paste, tunnel or collaborator host)",
                evidence=[host],
                halt=True,
            ))
        elif not any(_matches_domain(host, a) for a in allow):
            out.append(Finding(
                ruleId="egress.unlisted_domain",
                severity="medium",
                score=35,
                message=f"destination '{host}' is not on the egress allowlist",
                evidence=[host],
            ))

        # Localhost is how an agent reaches the governor's own API with a
        # stolen client token -- worth naming rather than silently allowing.
        if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            out.append(Finding(
                ruleId="egress.loopback_api",
                severity="high",
                score=50,
                message="request targets loopback — may be addressing the "
                        "governor's own API directly",
                evidence=[host],
            ))

    if hosts:
        session.record_egress(len(env.normalized_action), hosts[0])
    return out


@register("egress")
def proxy_evasion(env, policy, session) -> list[Finding]:
    out = []
    for pat, why in _PROXY_EVASION:
        m = pat.search(env.normalized_action)
        if m:
            out.append(Finding(
                ruleId="egress.proxy_evasion",
                severity="critical",
                score=100,
                message=f"network call configured to bypass mediation or verification ({why})",
                evidence=[m.group(0)[:120]],
                halt=True,
            ))
    return out


@register("egress")
def covert_channel(env, policy, session) -> list[Finding]:
    out = []
    for pat, rule_id, msg in (
        # Matched against the pre-decode view: the encoded label IS the signal,
        # and deobfuscating it first would delete the evidence.
        (_DNS_EXFIL, "egress.dns_exfil",
         "long encoded DNS label — consistent with DNS-tunnel exfiltration"),
        (_DOH, "egress.doh",
         "DNS-over-HTTPS — resolves names outside any local DNS visibility"),
        (_RAW_SOCKET, "egress.raw_socket",
         "raw socket — bypasses HTTP-level proxying entirely"),
        (_TUNNEL, "egress.tunnel",
         "reverse tunnel or relay — exposes this machine to an external endpoint"),
    ):
        m = pat.search(env.normalized_action) or pat.search(env.normalized_raw)
        if m:
            out.append(Finding(
                ruleId=rule_id, severity="critical", score=100,
                message=msg, evidence=[m.group(0)[:120]], halt=True))
    return out
