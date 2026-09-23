import pytest
import sys
import os

# Add executa directory to path for direct import
plugin_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../executas/sentinel-risk-scanner"))
if plugin_dir not in sys.path:
    sys.path.insert(0, plugin_dir)

from sentinel_risk_scanner_plugin import (
    invoke,
    scan_calldata,
    audit_token_safety,
    explain_revert,
    get_security_telemetry,
)

def test_ping():
    res = invoke("ping", {})
    assert res["success"] is True
    assert res["data"]["pong"] is True

def test_scan_calldata_unlimited_allowance():
    # 0x095ea7b3 + spender address (32 bytes) + 2**256 - 1 amount (32 bytes)
    spender = "0000000000000000000000001111111111111111111111111111111111111111"
    max_uint256 = "f" * 64
    calldata = f"0x095ea7b3{spender}{max_uint256}"
    to_addr = "0x4200000000000000000000000000000000000006"

    res = scan_calldata(calldata, to_addr)
    assert res["status"] == "completed"
    assert res["selector"] == "0x095ea7b3"
    assert res["method"] == "approve(address,uint256)"
    assert res["threat_level"] == "CRITICAL_RISK"
    assert any("UNLIMITED_ALLOWANCE_APPROVAL" in r for r in res["risks"])

def test_scan_calldata_safe_transfer():
    # 0xa9059cbb + recipient (32 bytes) + amount 1 ETH (32 bytes)
    recipient = "0000000000000000000000002222222222222222222222222222222222222222"
    amount = "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
    calldata = f"0xa9059cbb{recipient}{amount}"
    to_addr = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"

    res = scan_calldata(calldata, to_addr)
    assert res["status"] == "completed"
    assert res["selector"] == "0xa9059cbb"
    assert res["method"] == "transfer(address,uint256)"
    assert res["threat_level"] == "SAFE"
    assert len(res["risks"]) == 0

def test_explain_revert_panic_overflow():
    # 0x4e487b71 + 0x11 (arithmetic overflow) padded to 32 bytes
    panic_overflow = "0x4e487b71" + "0" * 62 + "11"
    res = explain_revert(panic_overflow)
    assert res["error_type"] == "SolidityPanic"
    assert res["panic_code"] == "0x11"
    assert "Arithmetic underflow or overflow" in res["description"]

def test_explain_revert_custom_allowance():
    # 0x83883344 (InsufficientAllowance())
    res = explain_revert("0x83883344")
    assert res["error_type"] == "CustomSolidityError"
    assert res["error_name"] == "InsufficientAllowance()"
    assert "Spender allowance is lower" in res["root_cause"]

def test_audit_token_safety():
    token = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" # USDC on Base
    res = audit_token_safety(token, "base")
    assert res["token_address"] == token
    assert res["chain"] == "base"
    assert res["security_score"] >= 90
    assert res["is_honeypot"] is False

def test_get_security_telemetry():
    res = get_security_telemetry()
    assert res["engine_version"] == "2.4.0"
    assert res["transactions_inspected"] > 0
    assert res["critical_threats_blocked"] > 0
    assert "base" in res["supported_chains"]

def test_invoke_dispatcher_envelope():
    res = invoke("get_security_telemetry", {})
    assert res["success"] is True
    assert "engine_version" in res["data"]
