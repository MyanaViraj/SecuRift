/**
 * SecuRift Frontend Interactive Engine
 * Handles real-time rule syntax validation, async TP/FP classifications,
 * Chart.js rendering, modals, and SOC notification toasts.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Auto-dismiss alerts after 6 seconds
    const flashAlerts = document.querySelectorAll(".soc-alert");
    flashAlerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = "opacity 0.5s ease";
            alert.style.opacity = "0";
            setTimeout(() => alert.remove(), 500);
        }, 6000);
    });

    // Mobile sidebar toggle if hamburger button exists
    const menuToggle = document.getElementById("sidebarToggle");
    const sidebar = document.querySelector(".app-sidebar");
    if (menuToggle && sidebar) {
        menuToggle.addEventListener("click", () => {
            sidebar.classList.toggle("show");
        });
    }

    // Initialize syntax live validator if on rule form
    initRuleSyntaxValidator();
});

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

/**
 * Validates Snort rule syntax via API or local parser
 */
function initRuleSyntaxValidator() {
    const ruleInput = document.getElementById("rule_text");
    const validateBtn = document.getElementById("btnValidateRule");
    const resultBox = document.getElementById("validationResultBox");

    if (!ruleInput || !validateBtn || !resultBox) return;

    validateBtn.addEventListener("click", async () => {
        const text = ruleInput.value.trim();
        if (!text) {
            resultBox.innerHTML = `
                <div class="soc-alert soc-alert-warning" style="margin-top: 0.75rem;">
                    Please enter a Snort rule string before testing syntax.
                </div>
            `;
            return;
        }

        resultBox.innerHTML = `
            <div style="color: var(--cyan-accent); font-size: 0.85rem; margin-top: 0.5rem;">
                Validating rule syntax...
            </div>
        `;

        try {
            const resp = await fetch("/rules/api/validate", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCsrfToken()
                },
                body: JSON.stringify({ rule_text: text })
            });
            const data = await resp.json();

            if (data.is_valid) {
                let warnHtml = "";
                if (data.warnings && data.warnings.length > 0) {
                    warnHtml = `<div style="font-size: 0.8rem; margin-top: 0.4rem; color: #fbbf24;">
                        Warnings: ${data.warnings.join("; ")}
                    </div>`;
                }

                resultBox.innerHTML = `
                    <div class="soc-alert soc-alert-success" style="margin-top: 0.75rem; flex-direction: column; align-items: flex-start;">
                        <div><strong>VALID SNORT RULE</strong> (${data.mode})</div>
                        ${warnHtml}
                        <div style="font-size: 0.75rem; margin-top: 0.35rem; color: #cbd5e1;">
                            Detected SID: <strong>${data.parsed.sid || 'N/A'}</strong> | 
                            Action: <strong>${data.parsed.action}</strong> | 
                            Protocol: <strong>${data.parsed.protocol}</strong> | 
                            Msg: <em>"${data.parsed.message || 'N/A'}"</em>
                        </div>
                    </div>
                `;

                // Auto-fill form fields if present
                const sidInput = document.getElementById("sid");
                const msgInput = document.getElementById("message");
                const protoSelect = document.getElementById("protocol");
                const actionSelect = document.getElementById("action");

                if (sidInput && data.parsed.sid && !sidInput.value) sidInput.value = data.parsed.sid;
                if (msgInput && data.parsed.message && !msgInput.value) msgInput.value = data.parsed.message;
                if (protoSelect && data.parsed.protocol) protoSelect.value = data.parsed.protocol;
                if (actionSelect && data.parsed.action) actionSelect.value = data.parsed.action;

            } else {
                resultBox.innerHTML = `
                    <div class="soc-alert soc-alert-danger" style="margin-top: 0.75rem; flex-direction: column; align-items: flex-start;">
                        <div><strong>SYNTAX ERROR DETECTED</strong></div>
                        <ul style="margin-left: 1.25rem; font-size: 0.8rem; margin-top: 0.35rem;">
                            ${data.errors.map(e => `<li>${e}</li>`).join("")}
                        </ul>
                    </div>
                `;
            }
        } catch (err) {
            resultBox.innerHTML = `
                <div class="soc-alert soc-alert-danger" style="margin-top: 0.75rem;">
                    Communication error with validator endpoint: ${err.message}
                </div>
            `;
        }
    });
}

/**
 * Updates an alert's classification (True Positive / False Positive / Unknown)
 */
async function classifyAlert(alertId, classification) {
    try {
        const resp = await fetch(`/false-positives/api/classify/${alertId}`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": getCsrfToken()
            },
            body: JSON.stringify({ classification: classification })
        });
        const data = await resp.json();

        if (data.success) {
            // Update badge in table
            const badge = document.getElementById(`badge-alert-${alertId}`);
            if (badge) {
                badge.textContent = classification;
                badge.className = `badge-soc ${classification === 'True Positive' ? 'pass' : (classification === 'False Positive' ? 'fail' : 'pending')}`;
            }

            // Update stats if summary cards exist
            if (data.metrics) {
                const tpEl = document.getElementById("metric-tp");
                const fpEl = document.getElementById("metric-fp");
                const drEl = document.getElementById("metric-dr");
                const fprEl = document.getElementById("metric-fpr");

                if (tpEl) tpEl.textContent = data.metrics.true_positives;
                if (fpEl) fpEl.textContent = data.metrics.false_positives;
                if (drEl) drEl.textContent = `${data.metrics.detection_rate}%`;
                if (fprEl) fprEl.textContent = `${data.metrics.false_positive_rate}%`;
            }

            if (data.triage) {
                const revEl = document.getElementById("triage-reviewed");
                const unkEl = document.getElementById("triage-unknown");
                if (revEl) revEl.textContent = data.triage.reviewed_alerts;
                if (unkEl) unkEl.textContent = data.triage.unknown_alerts;
            }

            showToast(`Alert #${alertId} marked as ${classification}`, "success");
        } else {
            showToast(`Failed to update: ${data.error}`, "danger");
        }
    } catch (err) {
        showToast(`Request failed: ${err.message}`, "danger");
    }
}

/**
 * Toast notifications
 */
function showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.className = `soc-alert soc-alert-${type}`;
    toast.style.position = "fixed";
    toast.style.bottom = "20px";
    toast.style.right = "20px";
    toast.style.zIndex = "9999";
    toast.style.boxShadow = "0 4px 15px rgba(0,0,0,0.5)";
    toast.innerHTML = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.transition = "opacity 0.4s ease";
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}
