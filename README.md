# Sentinel Web3 Risk Scanner (Anna AI OS)

AI-Native Web3 Security Intelligence, Transaction Intent Reasoning, and Pre-Execution Threat Diagnostic Engine for the Anna AI OS desktop and chat agent.

## Core Capabilities
- **AI Intent Divergence Engine:** Cross-references declared natural language user intent (e.g. claiming airdrops, swapping tokens, minting NFTs) against low-level EVM bytecode execution to identify covert phishing drainers and malicious approvals.
- **Multi-Signal Causal Exploit Correlation:** Unifies EVM control flow, ERC-20 state differentials, and ABI verification into an actionable causal attack graph with blast radius quantification.
- **Context-Aware Remediation & Safe Calldata Synthesis:** Automatically synthesizes exact bounded calldata replacements (e.g. capping unlimited approvals to exact trade notionals) with one-click copying and step-by-step mitigation protocols.
- **Pre-Execution Calldata Threat Analysis:** Intercepts and parses raw EVM calldata to flag dangerous unlimited token approvals (`type(uint256).max`), unverified function selectors, and suspicious routing.
- **Token Safety & Honeypot Audit:** Analyzes ERC-20 smart contracts for honeypot transfer restrictions, excessive buy/sell taxes, mint privileges, and proxy vulnerabilities on Base, Ethereum, Optimism, and Arbitrum.
- **EVM Revert & Panic Diagnostics:** Decodes raw return bytes and Solidity panic codes (`Panic(0x11)` arithmetic overflow, `Panic(0x32)` out-of-bounds, custom DEX slippage errors) into root causes and actionable remedies.
- **Deterministic Safety Standards:** Built with strict bounded execution, function length $\le 60$ lines, assertion density $\ge 2$, and zero external unauthenticated network dependencies.

## Architecture

```
                      +-----------------------------+
                      |      Anna AI OS Desktop     |
                      |        (Host Window)        |
                      +--------------+--------------+
                                     |
                                postMessage
                                     |
                                     v
                      +-----------------------------+
                      |  Static Web Bundle (SPA)    |
                      |    (HTML5 / Glassmorphic)   |
                      +--------------+--------------+
                                     |
                           Host Dispatcher JSON-RPC
                                     |
                                     v
                      +-----------------------------+
                      |       Executa Plugin        |
                      | (sentinel_risk_scanner.py)  |
                      +-----------------------------+
```

## Verification

```bash
# Run automated pytest suite
pytest tests/ -v

# Validate Anna App schema
anna-app validate
```

## License
MIT License.
