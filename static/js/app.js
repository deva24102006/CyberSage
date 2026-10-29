/**
 * Cyber Mistake Detector - Frontend Client Script
 * Provides:
 * - Real-time client-side search & category filtering
 * - Expand / Collapse all accordion toggle
 * - 1-Click CLI command clipboard copy
 * - Print / PDF export
 * - Scan overlay & button loading state
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Scan Form Submission & Loading Overlay
    const scanForms = document.querySelectorAll("form.scan-form");
    const scanOverlay = document.getElementById("scanOverlay");

    scanForms.forEach((form) => {
        form.addEventListener("submit", () => {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = `<span>&#x23F3;</span> Scanning System...`;
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
                ? `<span>&#x25B2;</span> Collapse All Guidance`
                : `<span>&#x25BC;</span> Expand All Guidance`;
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
                const originalText = btn.innerText;
                btn.innerText = "✓ Copied!";
                btn.style.borderColor = "#10b981";
                btn.style.color = "#34d399";

                setTimeout(() => {
                    btn.innerText = originalText;
                    btn.style.borderColor = "";
                    btn.style.color = "";
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
            // Expand all guidance accordions before printing so full report is captured in PDF
            const detailsElements = document.querySelectorAll(".recommendation-details");
            detailsElements.forEach((el) => (el.open = true));
            window.print();
        });
    }

    // 6. Interactive Remediation Verification & Dynamic Hygiene Score
    const verifyButtons = document.querySelectorAll(".btn-verify-fix");
    const resetBtn = document.getElementById("resetRemediationsBtn");
    const gaugeFill = document.querySelector(".gauge-fill");
    const meterScoreText = document.querySelector(".meter-score-text");
    const statSafe = document.querySelector(".stat-safe");
    const statWarn = document.querySelector(".stat-warn");
    const statHigh = document.querySelector(".stat-high");

    const STORAGE_KEY = "cybersage_remediated_checks";

    function getRemediatedChecks() {
        try {
            return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
        } catch {
            return [];
        }
    }

    function saveRemediatedChecks(list) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
        } catch (e) {
            console.error("Could not save to localStorage", e);
        }
    }

    function showToast(msg) {
        const existing = document.querySelector(".cyber-toast");
        if (existing) existing.remove();

        const toast = document.createElement("div");
        toast.className = "cyber-toast";
        toast.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            <span>${msg}</span>
        `;
        document.body.appendChild(toast);
        setTimeout(() => {
            if (toast && toast.parentNode) toast.remove();
        }, 4000);
    }

    function recalculateDashboard() {
        const cards = document.querySelectorAll(".result-card");
        if (!cards.length) return;

        let total = cards.length;
        let safeCount = 0;
        let warnCount = 0;
        let highCount = 0;

        cards.forEach((card) => {
            const status = (card.getAttribute("data-status") || "").toLowerCase();
            const severity = (card.getAttribute("data-severity") || "").toLowerCase();

            if (status === "safe") {
                safeCount++;
            } else if (status === "warning") {
                warnCount++;
                if (severity === "high") highCount++;
            }
        });

        const evaluated = safeCount + warnCount;
        const pct = evaluated > 0 ? Math.round((safeCount / evaluated) * 100) : 0;

        // Update score text
        if (meterScoreText) {
            meterScoreText.innerText = `${pct}%`;
        }

        // Update SVG circular gauge
        if (gaugeFill) {
            const circumference = 314.159;
            const offset = circumference - (pct / 100 * circumference);
            gaugeFill.style.strokeDashoffset = offset;
            if (pct >= 70) {
                gaugeFill.classList.remove("gauge-fill-warn");
                gaugeFill.classList.add("gauge-fill-safe");
            } else {
                gaugeFill.classList.remove("gauge-fill-safe");
                gaugeFill.classList.add("gauge-fill-warn");
            }
        }

        // Update Stat cards
        if (statSafe) statSafe.innerText = safeCount;
        if (statWarn) statWarn.innerText = warnCount;
        if (statHigh) statHigh.innerText = highCount;

        // Update filter pills
        const warnPill = document.querySelector('.filter-btn[data-filter="warning"]');
        if (warnPill) warnPill.innerText = `Weaknesses (${warnCount})`;
        const safePill = document.querySelector('.filter-btn[data-filter="safe"]');
        if (safePill) safePill.innerText = `Passed (${safeCount})`;
        const highPill = document.querySelector('.filter-btn[data-filter="high"]');
        if (highPill) highPill.innerText = `High Severity (${highCount})`;

        // Show/hide reset button
        const remediatedList = getRemediatedChecks();
        if (resetBtn) {
            resetBtn.style.display = remediatedList.length > 0 ? "inline-flex" : "none";
        }
    }

    function applyRemediation(checkName, buttonEl, persist) {
        const card = buttonEl.closest(".result-card");
        if (!card) return;

        // Update card visual state
        card.setAttribute("data-status", "safe");
        card.classList.remove("status-warning");
        card.classList.add("status-safe");

        // Update status badge
        const badge = card.querySelector(".status-badge");
        if (badge) {
            badge.className = "status-badge badge-safe";
            badge.innerText = "SAFE (REMEDIATED)";
        }

        // Update button
        buttonEl.classList.add("is-remediated");
        buttonEl.disabled = true;
        buttonEl.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg><span>✓ Remediated &amp; Verified</span>`;

        if (persist) {
            const list = getRemediatedChecks();
            if (!list.includes(checkName)) {
                list.push(checkName);
                saveRemediatedChecks(list);
            }
            recalculateDashboard();
            const currentPct = meterScoreText ? meterScoreText.innerText : "";
            showToast(`[${checkName}] verified as remediated! Score updated to ${currentPct}.`);
        }
    }

    // Attach click handlers to verify buttons
    verifyButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const checkName = btn.getAttribute("data-check-name");
            if (checkName) {
                applyRemediation(checkName, btn, true);
            }
        });
    });

    // Restore any previously saved remediations on page load
    const saved = getRemediatedChecks();
    if (saved.length > 0) {
        verifyButtons.forEach((btn) => {
            const checkName = btn.getAttribute("data-check-name");
            if (checkName && saved.includes(checkName)) {
                applyRemediation(checkName, btn, false);
            }
        });
        recalculateDashboard();
    }

    // Reset button handler
    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            localStorage.removeItem(STORAGE_KEY);
            window.location.reload();
        });
    }
});
