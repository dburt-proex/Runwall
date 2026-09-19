"""Shared vocabulary for interpreter invocation and process opacity."""
from __future__ import annotations
import re

_NAME = r"(?:python[0-9.]*|py|node|deno|bun|ruby|perl|php|pwsh|powershell|uv|npx|bash|zsh)"
_DIRECT = re.compile(rf"\b{_NAME}\b[^|;\n]*(\s-[ce]\b|\s-e\b|\s--eval\b|\s-m\s+[\w.]+|\s\S+\.(py|js|mjs|ts|rb|pl|php|ps1|sh))", re.I)
_BARE_SH = re.compile(r"(?<!\.)\bsh\b[^|;\n]*(\s-[ce]\b|\s--eval\b|\s\S+\.sh\b)", re.I)
_PIPE_SINK = re.compile(rf"\|\s*(?:xargs(?:\s+[^|;\n]+)?\s+)?{_NAME}\b(?:\s+-)?(?:\s|$)", re.I)
_PIPE_SH = re.compile(r"\|\s*(?:xargs(?:\s+[^|;\n]+)?\s+)?(?<!\.)\bsh\b(?:\s|$)", re.I)

def is_interpreter_invocation(text: str) -> bool:
    return bool(_DIRECT.search(text) or _BARE_SH.search(text) or _PIPE_SINK.search(text) or _PIPE_SH.search(text))
