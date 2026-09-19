"""Isolate Grok OAuth token files from the developer machine."""

import pytest


@pytest.fixture(autouse=True)
def isolate_jev_config(tmp_path, monkeypatch):
    monkeypatch.setenv("JEV_ULTRAFAST_CONFIG_DIR", str(tmp_path / "jev-ultrafast"))
    monkeypatch.delenv("TEXT_MODEL_API_KEY", raising=False)
