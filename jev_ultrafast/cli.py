"""CLI for Grok subscription OAuth (`jev-ultrafast login`)."""

from __future__ import annotations

import argparse
import sys
import time
import webbrowser

from .auth import AuthError, clear_tokens, load_tokens, poll_token, save_tokens, start_device_auth, token_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jev-ultrafast",
        description="Jev Ultrafast helpers. TypeSafe stays on TYPESAFE_API_KEY; this CLI signs in Grok for TYPE_TEXT.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("login", help="Sign in with a Grok subscription (device-code OAuth + PKCE)")
    sub.add_parser("logout", help="Forget saved Grok credentials")
    sub.add_parser("status", help="Show whether Grok credentials are stored")
    args = parser.parse_args(argv)
    try:
        if args.command == "login":
            return cmd_login()
        if args.command == "logout":
            return cmd_logout()
        return cmd_status()
    except AuthError as error:
        print(error, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


def cmd_login() -> int:
    device = start_device_auth()
    destination = device.verification_uri_complete or device.verification_uri
    print("Grok subscription login (xAI device-code OAuth)")
    print(f"Open: {destination}")
    print(f"Code: {device.user_code}")
    print("Waiting for authorization…")
    try:
        webbrowser.open(destination)
    except Exception:
        pass
    tokens = poll_token(device)
    path = save_tokens(tokens)
    print(f"Saved credentials to {path}")
    print("TYPE_TEXT will call https://api.x.ai/v1 with this token. TypeSafe is unchanged.")
    return 0


def cmd_logout() -> int:
    clear_tokens()
    print(f"Removed Grok credentials at {token_path()}")
    return 0


def cmd_status() -> int:
    tokens = load_tokens()
    path = token_path()
    if tokens is None:
        print(f"No saved Grok credentials at {path}")
        print("Run `jev-ultrafast login`, or set TEXT_MODEL_API_KEY for CI/dev.")
        return 1
    remaining = int(tokens.expires_at - time.time())
    if remaining > 0:
        print(f"Grok OAuth credentials present at {path} (access token expires in {remaining}s)")
    else:
        print(f"Grok OAuth credentials present at {path} (access token expired; refresh on next TYPE_TEXT)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
