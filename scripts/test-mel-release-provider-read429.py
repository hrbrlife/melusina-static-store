#!/usr/bin/env python3
"""Named read-only devnet 429 recovery and refusal checks."""

import importlib.util
import io
import json
import os
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch


provider_path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).with_name("mel-release-provider.py")
spec = importlib.util.spec_from_file_location("store_provider_read429", provider_path)
provider = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(provider)


class Clock:
    def __init__(self):
        self.value = 100.0
        self.sleeps = []

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


def throttled():
    return urllib.error.HTTPError("https://rpc.example", 429, "Too Many Requests", {}, None)


def response(account):
    return io.BytesIO(json.dumps({"result": {"value": account}}).encode())


def test_read_account_retries_429_then_finalized_account():
    clock = Clock()
    calls = []

    def read(request, timeout):
        payload = json.loads(request.data)
        assert payload["method"] == "getAccountInfo"
        assert payload["params"] == ["Pda123", {"encoding": "base64", "commitment": "finalized"}]
        calls.append(timeout)
        if len(calls) < 3:
            raise throttled()
        return response({"owner": "Registry123", "data": ["AAEC", "base64"]})

    with patch.dict(os.environ, {"MEL_RELEASE_RPC_URL": "https://rpc.example"}), \
            patch.object(provider.urllib.request, "urlopen", side_effect=read), \
            patch.object(provider.time, "monotonic", side_effect=clock.now), \
            patch.object(provider.time, "sleep", side_effect=clock.sleep):
        result = provider.read_account("Pda123", "finalized")
    assert result["owner"] == "Registry123"
    assert len(calls) == 3 and clock.sleeps == [1.0, 2.0]


def test_read_account_refuses_non429_without_retry():
    clock = Clock()
    calls = []

    def read(request, timeout):
        calls.append(timeout)
        raise urllib.error.HTTPError("https://rpc.example", 500, "Server Error", {}, None)

    with patch.dict(os.environ, {"MEL_RELEASE_RPC_URL": "https://rpc.example"}), \
            patch.object(provider.urllib.request, "urlopen", side_effect=read), \
            patch.object(provider.time, "monotonic", side_effect=clock.now), \
            patch.object(provider.time, "sleep", side_effect=clock.sleep):
        try:
            provider.read_account("Pda123", "finalized")
        except provider.ProviderError as exc:
            assert "HTTP Error 500" in str(exc)
        else:
            raise AssertionError("non-429 RPC failure was accepted")
    assert len(calls) == 1 and clock.sleeps == []


def test_read_account_refuses_persistent_429_at_bound():
    clock = Clock()
    calls = []

    def read(request, timeout):
        calls.append(timeout)
        raise throttled()

    with patch.dict(os.environ, {"MEL_RELEASE_RPC_URL": "https://rpc.example"}), \
            patch.object(provider.urllib.request, "urlopen", side_effect=read), \
            patch.object(provider.time, "monotonic", side_effect=clock.now), \
            patch.object(provider.time, "sleep", side_effect=clock.sleep):
        try:
            provider.read_account("Pda123", "finalized")
        except provider.ProviderError as exc:
            assert "HTTP 429 persisted for 60s" in str(exc)
        else:
            raise AssertionError("persistent throttle was accepted")
    assert 1 < len(calls) < 20 and sum(clock.sleeps) == 60.0


def test_read_account_refuses_rpc_error_without_retry():
    clock = Clock()
    with patch.dict(os.environ, {"MEL_RELEASE_RPC_URL": "https://rpc.example"}), \
            patch.object(provider.urllib.request, "urlopen", return_value=io.BytesIO(b'{"error":{"code":-32000}}')) as read, \
            patch.object(provider.time, "monotonic", side_effect=clock.now), \
            patch.object(provider.time, "sleep", side_effect=clock.sleep):
        try:
            provider.read_account("Pda123", "finalized")
        except provider.ProviderError as exc:
            assert "-32000" in str(exc)
        else:
            raise AssertionError("RPC error was accepted")
    assert read.call_count == 1 and clock.sleeps == []


if __name__ == "__main__":
    test_read_account_retries_429_then_finalized_account()
    test_read_account_refuses_non429_without_retry()
    test_read_account_refuses_persistent_429_at_bound()
    test_read_account_refuses_rpc_error_without_retry()
    print("read-only ReleaseEntry 429 tests passed")
