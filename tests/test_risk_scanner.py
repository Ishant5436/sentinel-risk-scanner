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

def test_scan_calldata_ai_reasoning_intent_divergence_phishing():
    spender = "0000000000000000000000001111111111111111111111111111111111111111"
    max_uint256 = "f" * 64
    calldata = f"0x095ea7b3{spender}{max_uint256}"
    to_addr = "0x4200000000000000000000000000000000000006"

    res = scan_calldata(calldata, to_addr, user_intent="Claim Community Airdrop & Rewards")
    assert "ai_reasoning" in res
    ai = res["ai_reasoning"]
    assert "intent_divergence" in ai
    assert "threat_correlation" in ai
    assert "context_remediation" in ai

    div = ai["intent_divergence"]
    assert div["verdict"] == "CRITICAL_INTENT_DIVERGENCE"
    assert div["divergence_score"] >= 90
    assert "airdrop" in div["reasoning"].lower() or "phishing" in div["reasoning"].lower()

    corr = ai["threat_correlation"]
    assert "Allowance Drain" in corr["attack_vector"]
    assert len(corr["signal_matrix"]) >= 1

    remed = ai["context_remediation"]
    assert remed["safe_calldata"] != calldata
    assert "ffffffffffffffff" not in remed["safe_calldata"]
    assert len(remed["remediation_steps"]) >= 2

def test_scan_calldata_ai_reasoning_aligned_swap():
    # 0x414bf389 (exactInputSingle)
    calldata = "0x414bf389" + "0" * 64 + "1" * 64
    to_addr = "0x2626664c2603336E57B271c5C0b26F421741e481"
    res = scan_calldata(calldata, to_addr, user_intent="Swap 500 USDC on Uniswap V3")

    assert "ai_reasoning" in res
    div = res["ai_reasoning"]["intent_divergence"]
    assert div["verdict"] == "ALIGNED_INTENT"
    assert div["divergence_score"] == 0

def test_scan_calldata_ai_reasoning_precondition_approval():
    spender = "0000000000000000000000001111111111111111111111111111111111111111"
    max_uint256 = "f" * 64
    calldata = f"0x095ea7b3{spender}{max_uint256}"
    to_addr = "0x4200000000000000000000000000000000000006"

    res = scan_calldata(calldata, to_addr, user_intent="Swap 500 USDC on Uniswap")
    assert "ai_reasoning" in res
    div = res["ai_reasoning"]["intent_divergence"]
    assert div["verdict"] == "PRECONDITION_STEP_DIVERGENCE"
    assert div["divergence_score"] == 40

def test_manifest_schema_compliance():
    from sentinel_risk_scanner_plugin import MANIFEST
    assert "name" in MANIFEST, "MANIFEST must have name"
    assert "display_name" in MANIFEST, "MANIFEST must have display_name (required by Anna protocol)"
    assert MANIFEST["display_name"] == "Sentinel Risk Scanner"
    assert MANIFEST["version"] == "1.1.0"
    assert isinstance(MANIFEST["tools"], list)
    for tool in MANIFEST["tools"]:
        assert "name" in tool
        assert "description" in tool
        assert isinstance(tool["parameters"], list), f"tool {tool['name']} parameters must be a list"
        for p in tool["parameters"]:
            assert "name" in p
            assert "type" in p
            assert "description" in p
            assert "required" in p

def test_protocol_dispatcher_methods():
    from sentinel_risk_scanner_plugin import handle_rpc_request
    # Initialize v2 handshake
    init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2.0"}}
    init_res = handle_rpc_request(init_req)
    assert init_res["result"]["protocolVersion"] == "2.0"
    assert init_res["result"]["serverInfo"]["name"] == "sentinel-risk-scanner"

    # Describe method
    desc_req = {"jsonrpc": "2.0", "id": 2, "method": "describe", "params": {}}
    desc_res = handle_rpc_request(desc_req)
    assert "result" in desc_res
    assert desc_res["result"]["display_name"] == "Sentinel Risk Scanner"

