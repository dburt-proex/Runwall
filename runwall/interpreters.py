"""Shared vocabulary for interpreter invocation and process opacity."""
from __future__ import annotations
import re

_NAME = r"(?:python[0-9.]*|py|node|deno|bun|ruby|perl|php|pwsh|powershell|uv|npx|bash|zsh)"
# In command position, bare "sh" is safe to include because a filename suffix
# cannot occupy the command slot. Accept common absolute/relative path-qualified
# executables and Windows .exe names as the same opaque interpreter boundary.
_EXEC_NAME = rf"(?:{_NAME}|sh)"
_PATH_PREFIX = r"(?:(?:[A-Za-z]:[\\/]|/|\./|\.\./)(?:[^\\/|;\n\"']+[\\/])*)?"
_EXEC = rf"{_PATH_PREFIX}{_EXEC_NAME}(?:\.exe)?"

_DIRECT = re.compile(
    rf"\b{_NAME}\b[^|;\n]*(\s-[ce]\b|\s-e\b|\s--eval\b|"
    rf"\s-m\s+[\w.]+|\s\S+\.(py|js|mjs|ts|rb|pl|php|ps1|sh))",
    re.I,
)
_BARE_SH = re.compile(
    r"(?<!\.)\bsh\b[^|;\n]*(\s-[ce]\b|\s--eval\b|\s\S+\.sh\b)", re.I
)
_PIPE_DIRECT = re.compile(rf"\|\s*{_EXEC}\b(?:\s+-)?(?:\s|$)", re.I)
# Parse only xargs options before the command token. Do not greedily skip an
# arbitrary command such as "grep" and then mistake its argument "python" for
# the process xargs will actually launch.
_XARGS_PIPE = re.compile(
    rf"\|\s*xargs\b(?:\s+-[^\s|;]+(?:\s+\d+)?)*"
    rf"\s+{_EXEC}\b(?:\s|$)",
    re.I,
)


def is_interpreter_invocation(text: str) -> bool:
    return bool(
        _DIRECT.search(text)
        or _BARE_SH.search(text)
        or _PIPE_DIRECT.search(text)
        or _XARGS_PIPE.search(text)
    )
