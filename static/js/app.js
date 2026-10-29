/**
 * Cyber Mistake Detector - Frontend Client Script
 *
 * Provides:
 * - Real-time client-side search & category filtering
 * - Keyboard shortcut support ('/' to focus search)
 * - Expand / Collapse all guidance accordions
 * - 1-Click CLI command clipboard copy
 * - Print / PDF export formatting
 * - Scan overlay & button loading state
 * - Authoritative backend-driven remediation verification (Zero client-side score fabrication)
 */

document.addEventListener("DOMContentLoaded", () => {
    // Purge any legacy localStorage remediation overrides so backend remains authoritative single source of truth
    try {
        localStorage.removeItem("cybersage_remediated_checks");
    } catch (_) {}

    // 1. Scan Form Submission & Loading Overlay
    const scanForms = document.querySelectorAll("form.scan-form");
    const scanOverlay = document.getElementById("scanOverlay");

    scanForms.forEach((form) => {
        form.addEventListener("submit", () => {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = `<span class="spinner-inline"></span> <span>Running System Audit...</span>`;
            }
            if (scanOverlay) {
                scanOverlay.style.display = "flex";
                scanOverlay.setAttribute("aria-busy", "true");
            }
        });
    });

    // 2. Real-Time Search & Category Filtering on Results Page
    const searchInput = document.getElementById("checkSearch");
    const filterBtns = document.querySelectorAll(".filter-btn");
    const resultCards = document.querySelectorAll(".result-card");
    const countDisplay = document.getElementById("visibleCheckCount");

    let currentFilter = "all";
    let searchQuery = "";

    function filterCards() {
        let visibleCount = 0;

        resultCards.forEach((card) => {
            const cardStatus = (card.getAttribute("data-status") || "").toLowerCase();
            const cardCategory = (card.getAttribute("data-category") || "").toLowerCase();
            const cardSeverity = (card.getAttribute("data-severity") || "").toLowerCase();
            const cardText = (card.innerText || "").toLowerCase();

            // Match category/status filter
            let matchesFilter = false;
            if (currentFilter === "all") {
                matchesFilter = true;
            } else if (currentFilter === "warning" && cardStatus === "warning") {
                matchesFilter = true;
            } else if (currentFilter === "safe" && cardStatus === "safe") {
                matchesFilter = true;
            } else if (currentFilter === "high" && cardSeverity === "high") {
                matchesFilter = true;
            } else if (currentFilter === "exploit" && cardCategory.includes("exploit")) {
                matchesFilter = true;
            } else if (currentFilter === "ransomware" && cardCategory.includes("ransomware")) {
                matchesFilter = true;
            } else if (currentFilter === "core" && cardCategory.includes("core")) {
                matchesFilter = true;
            }

            // Match search text query
            const matchesSearch = !searchQuery || cardText.includes(searchQuery);

            if (matchesFilter && matchesSearch) {
                card.style.display = "block";
                visibleCount++;
            } else {
                card.style.display = "none";
            }
        });

        if (countDisplay) {
            countDisplay.innerText = `Showing ${visibleCount} of ${resultCards.length} checks`;
        }
    }

    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            searchQuery = e.target.value.trim().toLowerCase();
            filterCards();
        });

        // Quick shortcut: Press '/' to focus search input
        window.addEventListener("keydown", (e) => {
            if (e.key === "/" && document.activeElement !== searchInput && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
                e.preventDefault();
                searchInput.focus();
                searchInput.select();
            }
        });
    }

    filterBtns.forEach((btn) => {
        btn.addEventListener("click", () => {
            filterBtns.forEach((b) => b.classList.remove("active"));
            btn.classList.add("active");
            currentFilter = btn.getAttribute("data-filter") || "all";
            filterCards();
        });
    });

    // 3. Expand / Collapse All Accordions
    const toggleAllBtn = document.getElementById("toggleAllAccordions");
    let allExpanded = false;

    if (toggleAllBtn) {
        toggleAllBtn.addEventListener("click", () => {
            allExpanded = !allExpanded;
            const detailsElements = document.querySelectorAll(".recommendation-details");
            detailsElements.forEach((el) => {
                el.open = allExpanded;
            });
            toggleAllBtn.innerHTML = allExpanded
                ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="18 15 12 9 6 15"/></svg><span>Collapse All Guidance</span>`
                : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg><span>Expand All Guidance</span>`;
        });
    }

    // 4. 1-Click Copy CLI Command to Clipboard
    const copyButtons = document.querySelectorAll(".btn-copy");
    copyButtons.forEach((btn) => {
        btn.addEventListener("click", async () => {
            const commandText = btn.getAttribute("data-copy") || "";
            if (!commandText) return;

            try {
                await navigator.clipboard.writeText(commandText);
                const originalHtml = btn.innerHTML;
                btn.innerHTML = `<span style="color: var(--status-safe-text);">✓ Copied</span>`;

                setTimeout(() => {
                    btn.innerHTML = originalHtml;
                }, 2000);
            } catch (err) {
                console.error("Clipboard copy failed: ", err);
            }
        });
    });

    // 5. Print / Save PDF Export
    const printBtn = document.getElementById("printReportBtn");
    if (printBtn) {
        printBtn.addEventListener("click", () => {
            const detailsElements = document.querySelectorAll(".recommendation-details");
            detailsElements.forEach((el) => (el.open = true));
            window.print();
        });
    }

    // 6. UI Toast Notifications
    function showToast(msg, type = "success") {
        const existing = document.querySelector(".cyber-toast");
        if (existing) existing.remove();

        const toast = document.createElement("div");
        toast.className = `cyber-toast ${type === "error" ? "toast-error" : ""}`;
        const icon = type === "error"
            ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
            : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;

        toast.innerHTML = `${icon}<span>${escapeHtml(msg)}</span>`;
        document.body.appendChild(toast);
        setTimeout(() => {
            if (toast && toast.parentNode) toast.remove();
        }, 5000);
    }

    function escapeHtml(str) {
        if (!str) return "";
        const div = document.createElement("div");
        div.innerText = str;
        return div.innerHTML;
    }

    // 7. Authoritative Backend Score Update (Reflects ONLY verified server data)
    function updateScoreDisplay(score, safeCount, warnCount) {
        const meterScoreText = document.querySelector(".meter-score-text");
        const statSafe = document.querySelector(".stat-safe");
        const statWarn = document.querySelector(".stat-warn");
        const scoreSegSafe = document.querySelector(".score-seg-safe");
        const scoreSegWarn = document.querySelector(".score-seg-warn");

        if (meterScoreText && typeof score === "number") {
            meterScoreText.innerText = `${score}%`;
        }

        if (statSafe && typeof safeCount === "number") statSafe.innerText = safeCount;
        if (statWarn && typeof warnCount === "number") statWarn.innerText = warnCount;

        // Update segmented score bar
        const total = resultCards.length || 12;
        if (scoreSegSafe && typeof safeCount === "number") {
            scoreSegSafe.style.width = `${Math.round((safeCount / total) * 100)}%`;
        }
        if (scoreSegWarn && typeof warnCount === "number") {
            scoreSegWarn.style.width = `${Math.round((warnCount / total) * 100)}%`;
        }

        // Update filter pills with authoritative counts
        if (typeof warnCount === "number") {
            const warnPill = document.querySelector('.filter-btn[data-filter="warning"]');
            if (warnPill) warnPill.innerText = `Weaknesses (${warnCount})`;
        }
        if (typeof safeCount === "number") {
            const safePill = document.querySelector('.filter-btn[data-filter="safe"]');
            if (safePill) safePill.innerText = `Passed (${safeCount})`;
        }
    }

    // 8. Authoritative Backend Remediation Verification Workflow
    const verifyButtons = document.querySelectorAll(".btn-verify-fix");

    verifyButtons.forEach((btn) => {
        btn.addEventListener("click", async () => {
            const controlId = btn.getAttribute("data-control-id");
            const checkName = btn.getAttribute("data-check-name") || controlId;
            const scanId = btn.getAttribute("data-scan-id") || window.CURRENT_SCAN_ID;
            const card = btn.closest(".result-card");
            const feedbackEl = card ? card.querySelector(".verify-feedback") : null;

            if (!controlId || !scanId) {
                showToast("Missing control identifier or scan reference.", "error");
                return;
            }

            // Set loading state
            const originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner-inline"></span> Probing Endpoint...`;

            if (feedbackEl) {
                feedbackEl.style.display = "none";
                feedbackEl.className = "verify-feedback";
            }

            try {
                const response = await fetch("/api/verify-control", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        scan_id: scanId,
                        control_id: controlId
                    })
                });

                const data = await response.json();

                if (response.ok && data.success === true) {
                    // Control is legitimately verified as SAFE by backend probe
                    if (card) {
                        card.setAttribute("data-status", "safe");
                        card.classList.remove("status-warning", "status-error", "status-unknown");
                        card.classList.add("status-safe");

                        const badge = card.querySelector(".status-badge");
                        if (badge) {
                            badge.className = "status-badge badge-safe";
                            badge.innerText = "SAFE (VERIFIED)";
                        }

                        const detailsEl = card.querySelector(".observed-state-text");
                        if (detailsEl && data.details) {
                            detailsEl.innerText = data.details;
                        }
                    }

                    btn.classList.add("is-remediated");
                    btn.disabled = true;
                    btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg><span>✓ Verified Safe</span>`;

                    if (feedbackEl) {
                        feedbackEl.className = "verify-feedback feedback-success";
                        feedbackEl.innerText = `✓ Live verification confirmed: ${data.message || "Setting is verified secure."}`;
                    }

                    if (typeof data.score === "number") {
                        updateScoreDisplay(data.score, data.safe_count, data.warning_count);
                    }

                    showToast(`[${checkName}] verified as SAFE! Hygiene score updated.`, "success");
                } else {
                    // Probe detected that setting is STILL INSECURE or inconclusive
                    // DO NOT MARK SAFE; SCORE DOES NOT CHANGE
                    btn.disabled = false;
                    btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg><span>Re-Verify Fix</span>`;

                    const errorMsg = data.message || "Control is still insecure on this endpoint. Score remains unchanged.";

                    if (feedbackEl) {
                        feedbackEl.className = "verify-feedback feedback-failure";
                        feedbackEl.innerText = `✗ Verification failed: ${errorMsg}`;
                    }

                    if (card && data.details) {
                        const detailsEl = card.querySelector(".observed-state-text");
                        if (detailsEl) {
                            detailsEl.innerText = data.details;
                        }
                    }

                    showToast(`Verification Failed: ${errorMsg}`, "error");
                }
            } catch (err) {
                console.error("Verification error:", err);
                btn.disabled = false;
                btn.innerHTML = originalHtml;

                if (feedbackEl) {
                    feedbackEl.className = "verify-feedback feedback-failure";
                    feedbackEl.innerText = "✗ Network communication error during endpoint probe.";
                }

                showToast("Failed to communicate with verification API.", "error");
            }
        });
    });
});
