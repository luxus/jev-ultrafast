"""TYPE_TEXT Grok OAuth token resolution. Offline httpx mocks; no paid APIs."""

import json
import time
from unittest.mock import Mock

from jev_ultrafast import auth, model
from jev_ultrafast.questions import TEXT_VALUE


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.is_error = status_code >= 400

    def json(self):
        return self._payload


def chat_payload(text="Zurich"):
    return {"choices": [{"message": {"content": json.dumps({"text": text})}}]}


def test_pkce_challenge_is_s256():
    pair = auth.generate_pkce()
    assert pair.method == "S256"
    assert len(pair.verifier) >= 43


def test_field_text_uses_oauth_store_without_api_key(monkeypatch):
    monkeypatch.delenv("TEXT_MODEL_API_KEY", raising=False)
    auth.save_tokens(
        auth.TokenSet(
            access_token="oauth-access",
            refresh_token="oauth-refresh",
            expires_at=time.time() + 3600,
        )
    )
    posts = []

    def fake_post(url, json=None, data=None, headers=None, **_kwargs):
        posts.append({"url": url, "json": json, "data": data, "headers": headers})
        return FakeResponse(chat_payload())

    monkeypatch.setattr(model.CLIENT, "post", fake_post)
    value, meta = model.field_text({"goal": 'Enter "Zurich"'})
    assert value == "Zurich"
    assert meta["model"] == "grok-4.6"
    assert len(posts) == 1
    sent = posts[0]
    assert sent["url"] == "https://api.x.ai/v1/chat/completions"
    assert sent["headers"]["Authorization"] == "Bearer oauth-access"
    assert sent["json"]["response_format"] == {"type": "json_object"}
    assert sent["json"]["model"] == "grok-4.6"
    assert "reasoning_effort" not in sent["json"]
    assert sent["json"]["messages"][0]["content"] == TEXT_VALUE
    assert json.loads(sent["json"]["messages"][1]["content"])["goal"] == 'Enter "Zurich"'
    assert sent["json"] is not None
    assert sent["data"] is None


def test_reasoning_effort_omits_none_for_grok_46_and_later():
    assert model.reasoning_effort("grok-4.6", "none") is None
    assert model.reasoning_effort("grok-4.6-fast", "none") is None
    assert model.reasoning_effort("grok-5", "none") is None
    assert model.reasoning_effort("xai/grok-4.6", "none") is None
    assert model.reasoning_effort("grok-4.3", "none") == "none"
    assert model.reasoning_effort("grok-4-fast", "none") == "none"
    assert model.reasoning_effort("grok-4.6", "low") == "low"
    assert model.reasoning_effort("grok-4.6", "") is None


def test_field_text_sends_reasoning_none_for_grok_43(monkeypatch):
    monkeypatch.setenv("TEXT_MODEL", "grok-4.3")
    monkeypatch.setenv("TEXT_MODEL_API_KEY", "ci-dev-key")
    posts = []

    def fake_post(url, json=None, **_kwargs):
        posts.append(json)
        return FakeResponse(chat_payload())

    monkeypatch.setattr(model.CLIENT, "post", fake_post)
    model.field_text({"goal": "Zurich"})
    assert posts[0]["model"] == "grok-4.3"
    assert posts[0]["reasoning_effort"] == "none"


def test_field_text_sends_explicit_reasoning_for_grok_46(monkeypatch):
    monkeypatch.setenv("TEXT_MODEL_REASONING", "low")
    monkeypatch.setenv("TEXT_MODEL_API_KEY", "ci-dev-key")
    posts = []

    def fake_post(url, json=None, **_kwargs):
        posts.append(json)
        return FakeResponse(chat_payload())

    monkeypatch.setattr(model.CLIENT, "post", fake_post)
    model.field_text({"goal": "Zurich"})
    assert posts[0]["model"] == "grok-4.6"
    assert posts[0]["reasoning_effort"] == "low"


def test_field_text_falls_back_to_env_key_without_store(monkeypatch):
    monkeypatch.setenv("TEXT_MODEL_API_KEY", "ci-dev-key")
    post = Mock(return_value=FakeResponse(chat_payload("London")))
    monkeypatch.setattr(model.CLIENT, "post", post)
    value, _meta = model.field_text({"goal": "Fly to London"})
    assert value == "London"
    assert post.call_count == 1
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer ci-dev-key"
    assert post.call_args.args[0] == "https://api.x.ai/v1/chat/completions"


def test_field_text_prefers_oauth_store_over_env_key(monkeypatch):
    monkeypatch.setenv("TEXT_MODEL_API_KEY", "should-not-be-used")
    auth.save_tokens(
        auth.TokenSet(access_token="oauth-access", refresh_token="rt", expires_at=time.time() + 3600)
    )
    post = Mock(return_value=FakeResponse(chat_payload()))
    monkeypatch.setattr(model.CLIENT, "post", post)
    model.field_text({"goal": "Zurich"})
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer oauth-access"


def test_field_text_refreshes_expired_oauth_token(monkeypatch):
    monkeypatch.delenv("TEXT_MODEL_API_KEY", raising=False)
    auth.save_tokens(
        auth.TokenSet(
            access_token="stale-access",
            refresh_token="refresh-me",
            expires_at=time.time() - 10,
            scope="api:access",
        )
    )
    posts = []

    def fake_post(url, json=None, data=None, headers=None, **_kwargs):
        posts.append({"url": url, "json": json, "data": data, "headers": headers})
        if url == auth.TOKEN_URL:
            assert data["grant_type"] == "refresh_token"
            assert data["refresh_token"] == "refresh-me"
            assert data["client_id"] == auth.CLIENT_ID
            return FakeResponse(
                {
                    "access_token": "fresh-access",
                    "refresh_token": "rotated-refresh",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                }
            )
        assert headers["Authorization"] == "Bearer fresh-access"
        return FakeResponse(chat_payload())

    monkeypatch.setattr(model.CLIENT, "post", fake_post)
    value, _meta = model.field_text({"goal": "Zurich"})
    assert value == "Zurich"
    assert [p["url"] for p in posts] == [auth.TOKEN_URL, "https://api.x.ai/v1/chat/completions"]
    stored = auth.load_tokens()
    assert stored is not None
    assert stored.access_token == "fresh-access"
    assert stored.refresh_token == "rotated-refresh"


def test_typesafe_choose_does_not_use_grok_oauth(monkeypatch):
    auth.save_tokens(
        auth.TokenSet(access_token="oauth-access", refresh_token="rt", expires_at=time.time() + 3600)
    )
    monkeypatch.setenv("TYPESAFE_API_KEY", "typesafe-key")
    captured = []
    state = {
        "url": "https://example.test/",
        "title": "Search",
        "text": "Search",
        "actions": [
            {"id": "e1", "kind": "fill", "label": "Search", "role": "textbox", "value": "", "node": 10},
            {"id": "wait", "kind": "wait", "label": "Wait"},
        ],
    }

    def fake_post(url, json=None, headers=None, **_kwargs):
        captured.append({"url": url, "headers": headers, "json": json})
        operations = json["questions"]["operation"]["criteria"]
        return FakeResponse(
            {
                "model": "jev-latest",
                "answers": {
                    "operation": {
                        "choice": "DONE",
                        "confidence": 1.0,
                        "probabilities": {key: float(key == "DONE") for key in operations},
                    }
                },
            }
        )

    monkeypatch.setattr(model.CLIENT, "post", fake_post)
    decision = model.choose(state, "Find a book", [])
    assert decision["operation"] == "DONE"
    assert captured[0]["url"] == "https://api.typesafe.ai/v1/systemone"
    assert captured[0]["headers"]["Authorization"] == "Bearer typesafe-key"
