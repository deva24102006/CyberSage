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
});
