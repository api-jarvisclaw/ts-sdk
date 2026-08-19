"""Generate cross-implementation reference fixtures from the Python SDK.

The TypeScript signers must produce byte-identical x402 envelopes to the Python
SDK, because both are verified by the same facilitator. Comparing against a
reference this SDK generated itself would only prove it is self-consistent, so
the reference comes from the already-live Python implementation instead.

Run from the ts-sdk directory with the python-sdk checked out as a sibling:

    python test/fixtures/generate_reference.py > test/fixtures/reference.json

Determinism comes from pinning the two sources of entropy — the random nonce and
the clock — to fixed values in both implementations.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

PYTHON_SDK = Path(__file__).resolve().parents[3] / "python-sdk"
if not PYTHON_SDK.is_dir():
    sys.exit(f"python-sdk not found at {PYTHON_SDK}")
sys.path.insert(0, str(PYTHON_SDK))

# A throwaway test key. Never used on any chain; present so both implementations
# sign the same message. Not a credential.
EVM_TEST_KEY = "0x" + "11" * 32
SOLANA_TEST_SEED_HEX = "22" * 32

FIXED_NONCE = bytes(range(32))
FIXED_MEMO = bytes(range(16))
FIXED_TIME = 1_700_000_000
FIXED_BLOCKHASH = "9zjKrPcvz9CQBHDeqNLuUYbFRcRDjs4jNM7GwSQtqPUZ"

CHALLENGE_EVM = {
    "x402Version": 2,
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:8453",
            "amount": "12345",
            "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "payTo": "0x2222222222222222222222222222222222222222",
            "maxTimeoutSeconds": 300,
            "extra": {"name": "USD Coin", "version": "2"},
        }
    ],
    "resource": {"description": "chat completion"},
}

CHALLENGE_SOLANA = {
    "x402Version": 2,
    "accepts": [
        {
            "scheme": "exact",
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "45678",
            "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "payTo": "3nLpqvJ6vLZ3sK4CvJ5v4qxA1JzRfLbYwGzT8pQ2xVwR",
            "maxTimeoutSeconds": 300,
            "extra": {"feePayer": "GkPqrQZBqDkSxWyEuJmPuNVMPhVUcvRcqiTfEUwmw3rW"},
        }
    ],
    "resource": {"description": "chat completion"},
}

RESOURCE_URL = "https://api.jarvisclaw.ai/v1/chat/completions"


class FakeResponse:
    """The minimum of `requests.Response` that the Python signers touch."""

    def __init__(self, body: dict):
        self._body = body
        self.headers: dict[str, str] = {}

    def json(self) -> dict:
        return self._body


def evm_reference() -> dict:
    import jarvisclaw.x402 as x402_mod
    from jarvisclaw.x402 import X402Signer

    real_urandom, real_time = os.urandom, time.time
    x402_mod.os.urandom = lambda n: FIXED_NONCE[:n]
    x402_mod.time.time = lambda: FIXED_TIME
    try:
        signer = X402Signer(EVM_TEST_KEY)
        header = signer.sign_from_402(FakeResponse(CHALLENGE_EVM), RESOURCE_URL)
    finally:
        x402_mod.os.urandom = real_urandom
        x402_mod.time.time = real_time

    return {
        "address": signer.address,
        "header": header,
        "envelope": json.loads(__import__("base64").b64decode(header)),
    }


def solana_reference() -> dict:
    import base58

    import jarvisclaw.x402_solana as sol_mod
    from jarvisclaw.x402_solana import SolanaX402Signer

    seed = bytes.fromhex(SOLANA_TEST_SEED_HEX)
    key_bs58 = base58.b58encode(seed).decode()

    signer = SolanaX402Signer(key_bs58)
    # Pin the two nondeterministic inputs: the blockhash normally comes from RPC
    # and the memo nonce from os.urandom.
    signer._get_blockhash = lambda base_url: FIXED_BLOCKHASH  # type: ignore[method-assign]
    real_urandom = sol_mod.os.urandom if hasattr(sol_mod, "os") else os.urandom
    os.urandom = lambda n: FIXED_MEMO[:n]  # type: ignore[assignment]
    try:
        header = signer.sign_from_402(FakeResponse(CHALLENGE_SOLANA), RESOURCE_URL, "")
    finally:
        os.urandom = real_urandom  # type: ignore[assignment]

    return {
        "address": signer.address,
        "seedHex": SOLANA_TEST_SEED_HEX,
        "keyBase58": key_bs58,
        "blockhash": FIXED_BLOCKHASH,
        "header": header,
        "envelope": json.loads(__import__("base64").b64decode(header)),
    }


if __name__ == "__main__":
    print(
        json.dumps(
            {
                "_generatedBy": "python-sdk via test/fixtures/generate_reference.py",
                "evmTestKey": EVM_TEST_KEY,
                "fixedNonceHex": FIXED_NONCE.hex(),
                "fixedMemoHex": FIXED_MEMO.hex(),
                "fixedTimeSeconds": FIXED_TIME,
                "resourceUrl": RESOURCE_URL,
                "challengeEvm": CHALLENGE_EVM,
                "challengeSolana": CHALLENGE_SOLANA,
                "evm": evm_reference(),
                "solana": solana_reference(),
            },
            indent=2,
        )
    )
