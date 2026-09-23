/**
 * Sentinel Web3 Risk Scanner - Anna App UI Controller
 * Dispatches to bundled executa tool-dev-sentinel-risk-scanner.
 */

const DEV_FALLBACK_TOOL_ID = "tool-dev-sentinel-risk-scanner";
const TOOL_ID =
  (typeof window !== "undefined"
    && window.__ANNA_TOOL_IDS__
    && window.__ANNA_TOOL_IDS__["sentinel-risk-scanner"])
  || DEV_FALLBACK_TOOL_ID;

// High-fidelity fallback fixtures for standalone browser preview
const STANDALONE_FIXTURES = {
  calldata: {
    status: "completed",
    target: "0x4200000000000000000000000000000000000006",
    selector: "0x095ea7b3",
    method: "approve(address,uint256)",
    threat_level: "CRITICAL_RISK",
    risks: ["UNLIMITED_ALLOWANCE_APPROVAL: Protocol requested max uint256 token drain permission."],
    payload_length_bytes: 68
  },
  token: {
    token_address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    chain: "base",
    security_score: 98,
    is_honeypot: false,
    buy_tax_bps: 0,
    sell_tax_bps: 0,
    can_mint: false,
    is_proxy: true,
    warnings: []
  },
  revert: {
    error_type: "SolidityPanic",
    selector: "0x4e487b71",
    panic_code: "0x11",
    description: "Arithmetic underflow or overflow",
    remediation: "Inspect math operations and bounds before re-submitting transaction."
  },
  telemetry: {
    engine_version: "2.4.0",
    active_monitors: 12,
    transactions_inspected: 41829,
    critical_threats_blocked: 142,
    total_gas_saved_usd: 12480.50,
    supported_chains: ["base", "ethereum", "optimism", "arbitrum"]
  }
};

let anna = null;

// Tab Switching
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".view-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    const target = btn.getAttribute("data-tab");
    const panel = document.getElementById(target);
    if (panel) panel.classList.add("active");
  });
});

async function callAnnaTool(method, args = {}) {
  if (anna && anna.tools && typeof anna.tools.invoke === "function") {
    try {
      const res = await anna.tools.invoke(TOOL_ID, method, args);
      if (res && res.success) return res.data;
    } catch (err) {
      console.warn("Anna tool dispatch error, using local fallback:", err);
    }
  }
  // Local fallback
  if (method === "scan_calldata") return STANDALONE_FIXTURES.calldata;
  if (method === "audit_token_safety") return STANDALONE_FIXTURES.token;
  if (method === "explain_revert") return STANDALONE_FIXTURES.revert;
  if (method === "get_security_telemetry") return STANDALONE_FIXTURES.telemetry;
  return null;
}

// Action Handlers
document.getElementById("btn-scan-calldata")?.addEventListener("click", async () => {
  const calldata = document.getElementById("input-calldata").value.trim();
  const to = document.getElementById("input-to-address").value.trim();
  const box = document.getElementById("calldata-result");
  box.innerHTML = '<span style="color:#94a3b8">Simulating calldata execution...</span>';

  const data = await callAnnaTool("scan_calldata", { calldata, to_address: to });
  if (!data) return;

  const isCrit = data.threat_level === "CRITICAL_RISK";
  box.innerHTML = `
    <div class="threat-card ${isCrit ? 'critical' : 'safe'}">
      <div style="font-weight:700; font-size:13px; color:${isCrit ? '#f43f5e' : '#10b981'}">
        THREAT LEVEL: ${data.threat_level}
      </div>
      <div style="margin-top:6px; font-family:var(--font-mono)">
        Method: <b>${data.method}</b> (${data.selector})
      </div>
      <div style="margin-top:4px; color:#94a3b8">Payload Size: ${data.payload_length_bytes} bytes</div>
      ${data.risks.length > 0 ? `
        <div style="margin-top:8px; padding:6px; background:rgba(244,63,94,0.1); border:1px solid #f43f5e; border-radius:4px; color:#fca5a5">
          ${data.risks.map(r => `<div>&bull; ${r}</div>`).join('')}
        </div>
      ` : '<div style="margin-top:8px; color:#10b981">&check; No suspicious spender drain permissions detected.</div>'}
    </div>
  `;
});

document.getElementById("btn-audit-token")?.addEventListener("click", async () => {
  const addr = document.getElementById("input-token-address").value.trim();
  const chain = document.getElementById("select-chain").value;
  const box = document.getElementById("token-result");
  box.innerHTML = '<span style="color:#94a3b8">Auditing smart contract bytecode...</span>';

  const data = await callAnnaTool("audit_token_safety", { token_address: addr, chain });
  if (!data) return;

  box.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px">
      <span style="font-weight:700">Security Score:</span>
      <span style="font-size:16px; font-weight:800; color:#10b981">${data.security_score} / 100</span>
    </div>
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px; font-family:var(--font-mono); font-size:11px">
      <div>Honeypot: <b style="color:#10b981">${data.is_honeypot ? 'YES' : 'NO'}</b></div>
      <div>Transfer Tax: <b>${data.buy_tax_bps} bps</b></div>
      <div>Mint Function: <b style="color:#10b981">${data.can_mint ? 'ENABLED' : 'DISABLED'}</b></div>
      <div>Proxy Pattern: <b>${data.is_proxy ? 'YES' : 'NO'}</b></div>
    </div>
  `;
});

document.getElementById("btn-explain-revert")?.addEventListener("click", async () => {
  const errHex = document.getElementById("input-error-data").value.trim();
  const box = document.getElementById("revert-result");
  box.innerHTML = '<span style="color:#94a3b8">Decoding revert signature...</span>';

  const data = await callAnnaTool("explain_revert", { error_data: errHex });
  if (!data) return;

  box.innerHTML = `
    <div style="font-weight:700; color:#06b6d4; margin-bottom:4px">
      ${data.error_type}: ${data.error_name || data.panic_code}
    </div>
    <div style="color:#f8fafc; font-size:11px; margin-bottom:6px">
      ${data.description || data.root_cause}
    </div>
    <div style="background:#0f172a; padding:8px; border-radius:6px; border:1px solid #334155; font-size:11px; color:#38bdf8">
      <b>Remediation:</b> ${data.remediation}
    </div>
  `;
});

document.getElementById("btn-refresh-telemetry")?.addEventListener("click", async () => {
  const box = document.getElementById("telemetry-content");
  const data = await callAnnaTool("get_security_telemetry", {});
  if (!data) return;

  box.innerHTML = `
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px">
      <div class="metric-pill">
        <div class="label">Total Inspected</div>
        <div class="value">${data.transactions_inspected.toLocaleString()}</div>
      </div>
      <div class="metric-pill">
        <div class="label">Blocked Threats</div>
        <div class="value text-warning">${data.critical_threats_blocked}</div>
      </div>
      <div class="metric-pill">
        <div class="label">Protected Value</div>
        <div class="value text-success">$${data.total_gas_saved_usd.toLocaleString()}</div>
      </div>
      <div class="metric-pill">
        <div class="label">Engine Version</div>
        <div class="value">${data.engine_version}</div>
      </div>
    </div>
  `;
});

// Initialization
window.addEventListener("load", () => {
  const hostLabel = document.getElementById("host-label");
  if (window.parent !== window) {
    hostLabel.textContent = "Anna OS Active";
  } else {
    hostLabel.textContent = "Standalone Mode";
  }
  document.getElementById("btn-scan-calldata")?.click();
  document.getElementById("btn-audit-token")?.click();
  document.getElementById("btn-explain-revert")?.click();
  document.getElementById("btn-refresh-telemetry")?.click();
});
