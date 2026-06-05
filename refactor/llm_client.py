"""
refactor/llm_client.py
----------------------
Configurable LLM API wrapper.

Consumes: ContextPackage (from context.py)
Produces: LLMResponse | None

Responsibilities:
  - Call the configured LLM provider with the rendered prompt
  - Parse the JSON response into a typed LLMResponse
  - Retry up to MAX_RETRIES times, appending the parse error to the prompt
  - Track token usage for cost reporting in the eval harness
  - Never raise on API or parse failure except for missing/bad credentials

Supported providers:
  - openrouter: default, uses OpenRouter's OpenAI-compatible API
  - openai-compatible: any Chat Completions-compatible endpoint
  - anthropic: optional, used only when explicitly configured
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

import httpx

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

from refactor.models import ContextPackage, FixKind, LLMResponse

if load_dotenv is not None:
    load_dotenv()


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

DEFAULT_PROVIDER = "openrouter"
DEFAULT_OPENROUTER_MODEL = "openrouter/free"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-20250514"

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENAI_BASE_URL = "https://api.openai.com/v1"

MAX_TOKENS = 2048
MAX_RETRIES = 2
TEMPERATURE = 0.1
REQUEST_TIMEOUT = 60.0

SYSTEM_PROMPT = (
    "You are a C security expert performing automated code review. "
    "You will be given a C function with a specific bug identified "
    "by static analysis. Your response must be a single valid JSON "
    "object with no surrounding text or markdown fences. "
    "The corrected_code field must contain the complete, compilable "
    "function - not a snippet or a diff."
)


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    api_key: str
    base_url: Optional[str] = None


def _get_config() -> LLMConfig:
    """
    Read LLM configuration from environment.

    Common settings:
      LLM_PROVIDER=openrouter | openai-compatible | anthropic
      LLM_MODEL=<provider model id>
      LLM_API_KEY=<generic fallback key>

    Provider-specific key fallbacks:
      OPENROUTER_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY

    For OpenAI-compatible local/proxy providers:
      LLM_BASE_URL=https://your-provider.example/v1
    """
    provider = os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER).strip().lower()

    if provider == "openrouter":
        return LLMConfig(
            provider=provider,
            model=os.getenv("LLM_MODEL", DEFAULT_OPENROUTER_MODEL),
            api_key=_require_api_key("OPENROUTER_API_KEY", provider),
            base_url=os.getenv("LLM_BASE_URL", OPENROUTER_BASE_URL),
        )

    if provider in {"openai", "openai-compatible", "openai_compatible"}:
        return LLMConfig(
            provider="openai-compatible",
            model=os.getenv("LLM_MODEL", DEFAULT_OPENAI_MODEL),
            api_key=_require_api_key("OPENAI_API_KEY", provider),
            base_url=os.getenv("LLM_BASE_URL", OPENAI_BASE_URL),
        )

    if provider == "anthropic":
        return LLMConfig(
            provider=provider,
            model=os.getenv("LLM_MODEL", DEFAULT_ANTHROPIC_MODEL),
            api_key=_require_api_key("ANTHROPIC_API_KEY", provider),
        )

    raise EnvironmentError(
        f"Unsupported LLM_PROVIDER={provider!r}. "
        "Use openrouter, openai-compatible, or anthropic."
    )


def _require_api_key(provider_env_name: str, provider: str) -> str:
    api_key = os.getenv(provider_env_name) or os.getenv("LLM_API_KEY")
    if api_key:
        return api_key
    raise EnvironmentError(
        f"No API key configured for LLM_PROVIDER={provider!r}. "
        f"Set {provider_env_name}=... or the generic LLM_API_KEY=..."
    )


# ---------------------------------------------------------------------------
# USAGE TRACKING
# ---------------------------------------------------------------------------

@dataclass
class UsageStats:
    """
    Accumulated token usage across all LLM calls in a run.
    The eval harness reads this to report cost alongside quality metrics.
    """
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def update(self, usage: object) -> None:
        """Update from Anthropic-style or OpenAI-compatible usage data."""
        if usage is None:
            return

        if isinstance(usage, dict):
            self.input_tokens += int(usage.get("prompt_tokens", 0) or 0)
            self.input_tokens += int(usage.get("input_tokens", 0) or 0)
            self.output_tokens += int(usage.get("completion_tokens", 0) or 0)
            self.output_tokens += int(usage.get("output_tokens", 0) or 0)
            return

        self.input_tokens += int(getattr(usage, "input_tokens", 0) or 0)
        self.input_tokens += int(getattr(usage, "prompt_tokens", 0) or 0)
        self.output_tokens += int(getattr(usage, "output_tokens", 0) or 0)
        self.output_tokens += int(getattr(usage, "completion_tokens", 0) or 0)


_usage = UsageStats()


def get_usage() -> UsageStats:
    return _usage


def reset_usage() -> None:
    global _usage
    _usage = UsageStats()


# ---------------------------------------------------------------------------
# PUBLIC ENTRYPOINT
# ---------------------------------------------------------------------------

def call(package: ContextPackage) -> Optional[LLMResponse]:
    """
    Call the configured LLM with the context package's rendered prompt.
    Returns a parsed LLMResponse on success, None on total failure.
    """
    config = _get_config()
    prompt = package.prompt
    last_error: Optional[str] = None

    for attempt in range(1, MAX_RETRIES + 2):
        if last_error and attempt > 1:
            prompt = _append_retry_instruction(prompt, last_error, attempt)

        raw_response = _call_api(config, prompt)
        if raw_response is None:
            return None

        parsed, error = _parse_response(raw_response)
        if parsed is not None:
            return parsed

        last_error = error

    return None


# ---------------------------------------------------------------------------
# API CALLS
# ---------------------------------------------------------------------------

def _call_api(config: LLMConfig, prompt: str) -> Optional[str]:
    if config.provider in {"openrouter", "openai-compatible"}:
        return _call_openai_compatible(config, prompt)
    if config.provider == "anthropic":
        return _call_anthropic(config, prompt)
    raise EnvironmentError(f"Unsupported LLM provider: {config.provider}")


def _call_openai_compatible(config: LLMConfig, prompt: str) -> Optional[str]:
    """
    Call an OpenAI Chat Completions-compatible provider.

    OpenRouter, OpenAI, many local gateways, and several free/proxy services use
    this shape, so this is the broadest default path for open source users.
    """
    assert config.base_url is not None
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }

    if config.provider == "openrouter":
        headers.update(_openrouter_headers())

    payload = {
        "model": config.model,
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    }

    try:
        response = httpx.post(
            f"{config.base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in {401, 403}:
            raise EnvironmentError(
                f"{config.provider} authentication failed. Check your API key."
            ) from exc
        return None
    except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError):
        return None

    _usage.update(data.get("usage"))
    return _extract_openai_compatible_text(data)


def _openrouter_headers() -> dict[str, str]:
    headers = {}
    referer = os.getenv("OPENROUTER_HTTP_REFERER")
    title = os.getenv("OPENROUTER_APP_TITLE", "ast-refactor")
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-Title"] = title
    return headers


def _extract_openai_compatible_text(data: dict[str, Any]) -> Optional[str]:
    try:
        message = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        return None

    content = message.get("content")
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        text_parts = [
            item.get("text", "")
            for item in content
            if isinstance(item, dict) and item.get("type") in {None, "text"}
        ]
        return "".join(text_parts) or None

    return None


def _call_anthropic(config: LLMConfig, prompt: str) -> Optional[str]:
    """
    Call Anthropic only when explicitly selected.
    Keeps Anthropic out of the default import path for open source users.
    """
    try:
        import anthropic
    except ImportError as exc:
        raise EnvironmentError(
            "LLM_PROVIDER='anthropic' requires the anthropic package. "
            "Install it or switch to LLM_PROVIDER=openrouter."
        ) from exc

    try:
        client = anthropic.Anthropic(api_key=config.api_key)
        message = client.messages.create(
            model=config.model,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.AuthenticationError as exc:
        raise EnvironmentError(
            "Anthropic API authentication failed. Check your ANTHROPIC_API_KEY."
        ) from exc
    except (anthropic.RateLimitError, anthropic.APIError):
        return None
    except Exception:
        return None

    _usage.update(message.usage)
    if not message.content:
        return None
    return getattr(message.content[0], "text", None)


# ---------------------------------------------------------------------------
# RESPONSE PARSING
# ---------------------------------------------------------------------------

def _parse_response(raw: str) -> tuple[Optional[LLMResponse], Optional[str]]:
    """
    Parse the raw API response string into an LLMResponse.
    Returns (LLMResponse, None) on success.
    Returns (None, error_message) on failure.
    """
    cleaned = _strip_fences(raw.strip())

    json_str = _extract_json_object(cleaned)
    if json_str is None:
        return None, (
            f"Your response did not contain a JSON object. "
            f"Raw response started with: {raw[:120]!r}"
        )

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        return None, (
            f"Your response was not valid JSON. "
            f"Parse error: {exc.msg} at position {exc.pos}. "
            f"Ensure the corrected_code field value is a properly escaped string."
        )

    missing = [
        f for f in ("fix_kind", "corrected_code", "explanation", "confidence")
        if f not in data
    ]
    if missing:
        return None, (
            f"Your JSON response was missing required fields: {missing}. "
            f"All four fields are required."
        )

    fix_kind = _parse_fix_kind(data["fix_kind"])

    try:
        confidence = float(data["confidence"])
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.5

    corrected_code = data["corrected_code"]
    if not isinstance(corrected_code, str) or not corrected_code.strip():
        return None, (
            "The corrected_code field was empty or not a string. "
            "It must contain the complete corrected function as a string."
        )

    return LLMResponse(
        fix_kind=fix_kind,
        corrected_code=corrected_code.strip(),
        explanation=str(data.get("explanation", "")),
        confidence=confidence,
        raw_response=raw,
    ), None


def _parse_fix_kind(value: object) -> FixKind:
    if not isinstance(value, str):
        return FixKind.OTHER
    normalised = value.lower().strip()
    for member in FixKind:
        if member.value == normalised:
            return member
    return FixKind.OTHER


def _strip_fences(text: str) -> str:
    text = re.sub(r"^```(?:json)?\s*\n?", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n?```\s*$", "", text, flags=re.MULTILINE)
    return text.strip()


def _extract_json_object(text: str) -> Optional[str]:
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i, ch in enumerate(text[start:], start=start):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]

    return None


# ---------------------------------------------------------------------------
# RETRY PROMPT CONSTRUCTION
# ---------------------------------------------------------------------------

def _append_retry_instruction(
    original_prompt: str,
    error_message: str,
    attempt: int,
) -> str:
    return (
        f"{original_prompt}\n\n"
        f"---\n"
        f"CORRECTION REQUIRED (attempt {attempt}):\n"
        f"Your previous response could not be parsed. Error: {error_message}\n"
        f"Please respond again with ONLY a valid JSON object matching the schema above. "
        f"No markdown fences, no preamble text, just the JSON object starting with {{."
    )
