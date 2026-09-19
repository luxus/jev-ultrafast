"""Grok subscription OAuth for TYPE_TEXT. TypeSafe stays on TYPESAFE_API_KEY."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

# Pinned from auth.x.ai discovery and xai-org/grok-build config.rs (public client, no secret).
ISSUER = "https://auth.x.ai"
DEVICE_AUTHORIZATION_URL = f"{ISSUER}/oauth2/device/code"
TOKEN_URL = f"{ISSUER}/oauth2/token"
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
SCOPES = (
    "openid profile email offline_access grok-cli:access api:access "
    "conversations:read conversations:write workspaces:read workspaces:write"
)
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
REFERRER = "grok-build"
CODE_CHALLENGE_METHOD = "S256"
DEFAULT_DEVICE_POLL_INTERVAL = 5
SLOW_DOWN_INCREMENT = 5
DEFAULT_EXPIRES_IN = 3600
SKEW_SECONDS = 60

SleepFn = Callable[[float], None]
TimeFn = Callable[[], float]


class AuthError(RuntimeError):
    """OAuth or token-store failure."""


@dataclass(frozen=True)
class PkcePair:
    verifier: str
    challenge: str
    method: str = CODE_CHALLENGE_METHOD


@dataclass(frozen=True)
class DeviceAuthorization:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None
    expires_in: int
    interval: int
    pkce: PkcePair
    expires_at: float


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str | None
    expires_at: float
    token_type: str = "Bearer"
    scope: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "token_type": self.token_type,
            "scope": self.scope,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any], *, now: float | None = None) -> TokenSet:
        access = _optional_str(data.get("access_token"))
        if not access:
            raise AuthError("token payload is missing access_token")
        expires_at = data.get("expires_at")
        if expires_at is None:
            expires_in = data.get("expires_in", DEFAULT_EXPIRES_IN)
            try:
                expires_at = (now if now is not None else time.time()) + int(expires_in)
            except (TypeError, ValueError) as exc:
                raise AuthError("token payload expires_in is not an integer") from exc
        try:
            expires_at_ts = float(expires_at)
        except (TypeError, ValueError) as exc:
            raise AuthError("token payload expires_at is not a number") from exc
        return cls(
            access_token=access,
            refresh_token=_optional_str(data.get("refresh_token")),
            expires_at=expires_at_ts,
            token_type=_optional_str(data.get("token_type")) or "Bearer",
            scope=_optional_str(data.get("scope")),
        )


def generate_pkce() -> PkcePair:
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return PkcePair(verifier=verifier, challenge=challenge)


def config_dir() -> Path:
    override = os.environ.get("JEV_ULTRAFAST_CONFIG_DIR", "").strip()
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    root = Path(xdg) if xdg else Path.home() / ".config"
    return root / "jev-ultrafast"


def token_path() -> Path:
    return config_dir() / "credentials.json"


def load_tokens() -> TokenSet | None:
    path = token_path()
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthError(f"could not read Grok credentials at {path}") from exc
    if not isinstance(payload, dict):
        raise AuthError(f"Grok credentials at {path} are not a JSON object")
    return TokenSet.from_mapping(payload)


def save_tokens(tokens: TokenSet) -> Path:
    path = token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(tokens.to_json(), indent=2) + "\n"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(encoded)
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    os.chmod(path, 0o600)
    return path


def clear_tokens() -> None:
    path = token_path()
    try:
        path.unlink()
    except FileNotFoundError:
        return


def resolve_text_bearer() -> str:
    """OAuth store first; TEXT_MODEL_API_KEY is the CI/dev fallback."""
    tokens = load_tokens()
    if tokens is not None:
        return ensure_fresh(tokens).access_token
    key = os.environ.get("TEXT_MODEL_API_KEY", "").strip()
    if key:
        return key
    raise ValueError(
        "TYPE_TEXT needs a Grok subscription login (`jev-ultrafast login`) "
        "or TEXT_MODEL_API_KEY for CI/dev; no text is hardcoded or guessed by the executor."
    )


def start_device_auth(
    *,
    pkce: PkcePair | None = None,
    time_fn: TimeFn | None = None,
) -> DeviceAuthorization:
    now = (time_fn or time.time)()
    pkce = pkce or generate_pkce()
    status, payload = post_form(
        DEVICE_AUTHORIZATION_URL,
        {
            "client_id": CLIENT_ID,
            "scope": SCOPES,
            "referrer": REFERRER,
            "code_challenge": pkce.challenge,
            "code_challenge_method": pkce.method,
        },
    )
    if status >= 400:
        raise AuthError(_oauth_detail(status, payload, "device code request failed"))
    device_code = payload.get("device_code")
    user_code = payload.get("user_code")
    verification_uri = payload.get("verification_uri")
    if not device_code or not user_code or not verification_uri:
        raise AuthError("device code response is missing device_code, user_code, or verification_uri")
    user_code_s = str(user_code)
    if not all(ch.isalnum() or ch == "-" for ch in user_code_s):
        raise AuthError("server returned invalid user_code format")
    _validate_verification_uri(str(verification_uri))
    complete = payload.get("verification_uri_complete")
    if complete:
        _validate_verification_uri(str(complete))
    expires_in = int(payload.get("expires_in") or 600)
    interval = int(payload.get("interval") or DEFAULT_DEVICE_POLL_INTERVAL)
    return DeviceAuthorization(
        device_code=str(device_code),
        user_code=user_code_s,
        verification_uri=str(verification_uri),
        verification_uri_complete=str(complete) if complete else None,
        expires_in=expires_in,
        interval=max(interval, 1),
        pkce=pkce,
        expires_at=now + expires_in,
    )


def poll_token(
    device_auth: DeviceAuthorization,
    *,
    sleep: SleepFn | None = None,
    time_fn: TimeFn | None = None,
) -> TokenSet:
    sleep_fn: SleepFn = sleep or time.sleep
    clock: TimeFn = time_fn or time.time
    interval = float(device_auth.interval)
    while True:
        sleep_fn(interval)
        now = clock()
        if now >= device_auth.expires_at:
            raise AuthError("device code expired; run `jev-ultrafast login` again")
        status, payload = post_form(
            TOKEN_URL,
            {
                "grant_type": DEVICE_GRANT_TYPE,
                "client_id": CLIENT_ID,
                "device_code": device_auth.device_code,
                "code_verifier": device_auth.pkce.verifier,
            },
        )
        if payload.get("access_token"):
            return TokenSet.from_mapping(payload, now=now)
        error = payload.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += SLOW_DOWN_INCREMENT
            continue
        if error in {"expired_token", "expired"}:
            raise AuthError("device code expired; run `jev-ultrafast login` again")
        if error == "access_denied":
            raise AuthError("authorization denied")
        raise AuthError(_oauth_detail(status, payload, "device token poll failed"))


def ensure_fresh(tokens: TokenSet, *, time_fn: TimeFn | None = None) -> TokenSet:
    now = (time_fn or time.time)()
    if tokens.expires_at - SKEW_SECONDS > now:
        return tokens
    refreshed = refresh_access_token(tokens, time_fn=time_fn)
    save_tokens(refreshed)
    return refreshed


def refresh_access_token(tokens: TokenSet, *, time_fn: TimeFn | None = None) -> TokenSet:
    if not tokens.refresh_token:
        raise AuthError("Grok credentials expired; run `jev-ultrafast login` again")
    now = (time_fn or time.time)()
    status, payload = post_form(
        TOKEN_URL,
        {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": tokens.refresh_token,
        },
    )
    if payload.get("access_token"):
        refreshed = TokenSet.from_mapping(payload, now=now)
        if not refreshed.refresh_token:
            refreshed.refresh_token = tokens.refresh_token
        if refreshed.scope is None:
            refreshed.scope = tokens.scope
        return refreshed
    error = payload.get("error")
    if error in {"invalid_grant", "expired_token"} or status in {400, 401}:
        raise AuthError("Grok refresh token rejected; run `jev-ultrafast login` again")
    raise AuthError(_oauth_detail(status, payload, "token refresh failed"))


def post_form(url: str, data: dict[str, str]) -> tuple[int, dict[str, Any]]:
    from .model import CLIENT

    try:
        response = CLIENT.post(url, data=data, headers={"Accept": "application/json"})
    except httpx.HTTPError:
        raise AuthError("Grok OAuth connection failed") from None
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return response.status_code, payload


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _oauth_detail(status: int, payload: dict[str, Any], prefix: str) -> str:
    detail = payload.get("error_description") or payload.get("error") or ""
    return f"{prefix} (HTTP {status}){': ' + str(detail) if detail else ''}"


def _validate_verification_uri(uri: str) -> None:
    if any(ch.isascii() and ord(ch) < 32 for ch in uri):
        raise AuthError("server returned invalid verification URI")
    parsed = urlsplit(uri)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}:
        return
    raise AuthError("server returned unsupported verification URI scheme")
