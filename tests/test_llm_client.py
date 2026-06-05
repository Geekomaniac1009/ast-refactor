import httpx

from refactor.llm_client import (
    LLMConfig,
    _call_openai_compatible,
    _extract_json_object,
    _get_config,
    _parse_response,
    _strip_fences,
    get_usage,
    reset_usage,
)
from refactor.models import FixKind

VALID_RESPONSE = '''
{
  "fix_kind": "add_free",
  "corrected_code": "void f() { int *p = malloc(8); free(p); }",
  "explanation": "Added missing free() call before function returns.",
  "confidence": 0.95
}
'''

def test_parse_valid_response():
    result, error = _parse_response(VALID_RESPONSE)
    assert error is None
    assert result is not None
    assert result.fix_kind == FixKind.ADD_FREE
    assert result.confidence == 0.95
    assert "free(p)" in result.corrected_code

def test_parse_strips_markdown_fences():
    fenced = f"```json\n{VALID_RESPONSE.strip()}\n```"
    result, error = _parse_response(fenced)
    assert error is None
    assert result is not None

def test_parse_handles_preamble():
    with_preamble = f"Here is the corrected code:\n{VALID_RESPONSE.strip()}"
    result, error = _parse_response(with_preamble)
    assert error is None
    assert result is not None

def test_parse_missing_field_returns_error():
    bad = '{"fix_kind": "add_free", "corrected_code": "void f() {}"}'
    result, error = _parse_response(bad)
    assert result is None
    assert "missing" in error.lower()

def test_parse_invalid_json_returns_error():
    result, error = _parse_response("this is not json at all")
    assert result is None
    assert error is not None

def test_extract_json_handles_nested_braces():
    text = 'prefix {"a": "if (x) { return; }"} suffix'
    extracted = _extract_json_object(text)
    assert extracted == '{"a": "if (x) { return; }"}'

def test_default_config_uses_openrouter_free_router(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")

    config = _get_config()

    assert config.provider == "openrouter"
    assert config.model == "openrouter/free"
    assert config.api_key == "test-key"
    assert config.base_url == "https://openrouter.ai/api/v1"

def test_openai_compatible_config_can_use_custom_base_url(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "local-model")
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:1234/v1")

    config = _get_config()

    assert config.provider == "openai-compatible"
    assert config.model == "local-model"
    assert config.api_key == "test-key"
    assert config.base_url == "http://localhost:1234/v1"

def test_openai_compatible_call_extracts_text_and_usage(monkeypatch):
    reset_usage()
    captured = {}

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": VALID_RESPONSE,
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 11,
                    "completion_tokens": 7,
                },
            }

    def fake_post(url, headers, json, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("refactor.llm_client.httpx.post", fake_post)
    config = LLMConfig(
        provider="openrouter",
        model="openrouter/free",
        api_key="test-key",
        base_url="https://openrouter.ai/api/v1/",
    )

    raw = _call_openai_compatible(config, "fix this")

    assert raw == VALID_RESPONSE
    assert captured["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer test-key"
    assert captured["headers"]["X-Title"] == "ast-refactor"
    assert captured["json"]["model"] == "openrouter/free"
    assert captured["json"]["messages"][1] == {"role": "user", "content": "fix this"}
    assert get_usage().input_tokens == 11
    assert get_usage().output_tokens == 7

def test_openai_compatible_auth_error_is_clear(monkeypatch):
    class FakeResponse:
        status_code = 401

        def raise_for_status(self):
            request = httpx.Request("POST", "https://example.test/chat/completions")
            raise httpx.HTTPStatusError("unauthorized", request=request, response=self)

    monkeypatch.setattr(
        "refactor.llm_client.httpx.post",
        lambda *args, **kwargs: FakeResponse(),
    )
    config = LLMConfig(
        provider="openai-compatible",
        model="any",
        api_key="bad-key",
        base_url="https://example.test",
    )

    try:
        _call_openai_compatible(config, "fix this")
    except EnvironmentError as exc:
        assert "authentication failed" in str(exc)
    else:
        raise AssertionError("Expected an EnvironmentError for 401 auth failures")
