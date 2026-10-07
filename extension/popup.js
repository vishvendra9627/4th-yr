const API_URL = "https://fourth-yr.onrender.com/api/analyze";

const urlElement = document.getElementById("url");
const scanBtn = document.getElementById("scanBtn");

const loading = document.getElementById("loading");
const error = document.getElementById("error");
const result = document.getElementById("result");

const verdictElement = document.getElementById("verdict");
const scoreElement = document.getElementById("score");
const summaryElement = document.getElementById("summary");
const indicatorsElement = document.getElementById("indicators");

let currentUrl = "";


/* --------------------------------
   Get current Chrome tab
-------------------------------- */

async function getCurrentTab() {

    const tabs = await chrome.tabs.query({
        active: true,
        currentWindow: true
    });

    return tabs[0];

}


/* --------------------------------
   Display current URL
-------------------------------- */

async function loadCurrentWebsite() {

    try {

        const tab = await getCurrentTab();

        currentUrl = tab.url || "";

        urlElement.textContent = currentUrl;

    } catch (err) {

        urlElement.textContent = "Unable to get current website";

    }

}


/* --------------------------------
   Scan website
-------------------------------- */

async function scanWebsite() {

    if (!currentUrl) {

        showError("Could not detect the current website.");

        return;

    }

    setLoading(true);

    try {

        const response = await fetch(API_URL, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({

                type: "url",

                content: currentUrl

            })

        });


        if (!response.ok) {

            const errorData = await response.json().catch(() => ({}));

            throw new Error(
                errorData.error ||
                `Server returned ${response.status}`
            );

        }


        const data = await response.json();

        displayResult(data);


    } catch (err) {

        console.error(err);

        showError(
            "Could not connect to the phishing detection server. " +
            "Make sure Flask is running on localhost:5000."
        );

    } finally {

        setLoading(false);

    }

}


/* --------------------------------
   Display ML result
-------------------------------- */

function displayResult(data) {

    result.classList.remove("hidden");

    error.classList.add("hidden");


    /* Verdict */

    const verdict = data.verdict;

    verdictElement.className = "verdict";


    if (verdict === "safe") {

        verdictElement.classList.add("safe");

    }

    else if (verdict === "suspicious") {

        verdictElement.classList.add("suspicious");

    }

    else {

        verdictElement.classList.add("phishing");

    }


    verdictElement.textContent =
        data.verdictLabel || verdict;


    /* Score */

    scoreElement.textContent =
        data.confidenceScore ?? 0;


    /* Summary */

    summaryElement.textContent =
        data.summary || "";


    /* Indicators */

    indicatorsElement.innerHTML = "";


    if (!data.indicators || data.indicators.length === 0) {

        indicatorsElement.innerHTML =
            `<div class="indicator low">
                No phishing indicators detected.
             </div>`;

        return;

    }


    data.indicators.forEach(indicator => {

        const div = document.createElement("div");

        div.className =
            `indicator ${indicator.severity || "low"}`;


        div.innerHTML = `
            <strong>${escapeHtml(indicator.name)}</strong>
            <br>
            <span>${escapeHtml(indicator.tip)}</span>
        `;


        indicatorsElement.appendChild(div);

    });

}


/* --------------------------------
   Loading state
-------------------------------- */

function setLoading(isLoading) {

    if (isLoading) {

        scanBtn.disabled = true;

        scanBtn.textContent = "Analyzing...";

        loading.classList.remove("hidden");

        result.classList.add("hidden");

        error.classList.add("hidden");

    }

    else {

        scanBtn.disabled = false;

        scanBtn.textContent = "🔍 Scan Website";

        loading.classList.add("hidden");

    }

}


/* --------------------------------
   Error
-------------------------------- */

function showError(message) {

    error.textContent = "⚠️ " + message;

    error.classList.remove("hidden");

    result.classList.add("hidden");

}


/* --------------------------------
   Basic HTML escaping
-------------------------------- */

function escapeHtml(value) {

    return String(value)

        .replace(/&/g, "&amp;")

        .replace(/</g, "&lt;")

        .replace(/>/g, "&gt;")

        .replace(/"/g, "&quot;")

        .replace(/'/g, "&#039;");

}


/* --------------------------------
   Events
-------------------------------- */

scanBtn.addEventListener(
    "click",
    scanWebsite
);


/* Load URL when popup opens */

loadCurrentWebsite();