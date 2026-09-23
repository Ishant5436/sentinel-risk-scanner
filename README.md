# Sentinel Web3 Risk Scanner (Anna AI OS)

Real-time on-chain transaction simulation, pre-execution calldata inspection, honeypot detection, and revert diagnostics for the Anna AI OS desktop and chat agent.

## Core Capabilities
- **Pre-Execution Calldata Threat Analysis:** Intercept and parse raw EVM calldata to flag dangerous unlimited token approvals (`type(uint256).max`), unverified function selectors, and suspicious routing.
- **Token Safety & Honeypot Audit:** Analyze ERC-20 smart contracts for honeypot transfer restrictions, excessive buy/sell taxes, mint privileges, and proxy vulnerabilities on Base, Ethereum, Optimism, and Arbitrum.
- **EVM Revert & Panic Diagnostics:** Decode raw return bytes and Solidity panic codes (`Panic(0x11)` arithmetic overflow, `Panic(0x32)` out-of-bounds, custom DEX slippage errors) into root causes and actionable remedies.
- **Deterministic Safety Standards:** Built with strict bounded execution, assertion density $\ge 2$, and zero external unauthenticated network dependencies.

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
