const API_BASE = '';

let currentMode = 'url';

const tabBtns    = document.querySelectorAll('.tab-btn');
const urlInput   = document.getElementById('url-input-wrap');
const emailInput = document.getElementById('email-input-wrap');
const analyzeBtn = document.getElementById('analyze-btn');
const resultsSec = document.getElementById('results-section');
const emptyState = document.getElementById('empty-state');

tabBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    currentMode = btn.dataset.mode;
    tabBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    urlInput.style.display   = currentMode === 'url'   ? 'block' : 'none';
    emailInput.style.display = currentMode === 'email' ? 'block' : 'none';
  });
});

analyzeBtn.addEventListener('click', runAnalysis);

document.getElementById('url-field')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') runAnalysis();
});

async function runAnalysis() {
  const content = currentMode === 'url'
    ? document.getElementById('url-field').value.trim()
    : document.getElementById('email-field').value.trim();

  if (!content) {
    shake(currentMode === 'url' ? document.getElementById('url-field') : document.getElementById('email-field'));
    return;
  }

  setLoading(true);

  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: currentMode, content })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server error ${res.status}`);
    }

    const data = await res.json();
    renderResults(data);
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

function renderResults(data) {
  emptyState.style.display = 'none';
  resultsSec.style.display = 'block';
  resultsSec.classList.remove('fade-in');
  void resultsSec.offsetWidth;
  resultsSec.classList.add('fade-in');


  const v = data.verdict;
  const verdictEl = document.getElementById('verdict-banner');
  verdictEl.className = `verdict-banner ${v}`;
  document.getElementById('verdict-icon').textContent  = data.verdictLabel || '';
  document.getElementById('verdict-label').textContent = data.verdictLabel;
  document.getElementById('verdict-summary').textContent = data.summary;

  renderScoreRing(data.confidenceScore, v);

  const high   = data.indicators.filter(i => i.severity === 'high').length;
  const medium = data.indicators.filter(i => i.severity === 'medium').length;
  const low    = data.indicators.filter(i => i.severity === 'low').length;

  document.getElementById('stat-total').textContent  = data.indicators.length;
  document.getElementById('stat-high').textContent   = high;
  document.getElementById('stat-medium').textContent = medium;
  document.getElementById('stat-low').textContent    = low;

  const modeEl = document.getElementById('analysis-mode');
  if (modeEl) {
    modeEl.textContent = data.analysisMode;
    modeEl.style.display = 'inline-flex';
  }

  if (data.mlProbability !== null && data.mlProbability !== undefined) {
    const mlEl = document.getElementById('ml-prob');
    if (mlEl) {
      mlEl.textContent = `ML confidence: ${data.mlProbability.toFixed(1)}% phishing probability`;
      mlEl.style.display = 'block';
    }
  }

  renderIndicators(data.indicators);
}

function renderScoreRing(score, verdict) {
  const colors = { safe: '#22c55e', suspicious: '#f59e0b', likely_phishing: '#ef4444' };
  const color = colors[verdict] || '#6b7280';
  const r = 36;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);

  const svgEl = document.getElementById('score-svg');
  const fillEl = document.getElementById('score-fill');
  const numEl  = document.getElementById('score-num');

  if (fillEl) {
    fillEl.setAttribute('stroke', color);
    fillEl.setAttribute('stroke-dasharray', circ);
    fillEl.setAttribute('stroke-dashoffset', circ);
    fillEl.setAttribute('cx', 45);
    fillEl.setAttribute('cy', 45);
    fillEl.setAttribute('r', r);
    setTimeout(() => {
      fillEl.setAttribute('stroke-dashoffset', offset);
    }, 50);
  }

  if (numEl) {
    numEl.textContent = score;
    numEl.style.color = color;
  }
}

function renderIndicators(indicators) {
  const list = document.getElementById('indicator-list');
  if (!indicators.length) {
    list.innerHTML = '<p style="color:var(--muted);font-size:.875rem;">No phishing indicators detected.</p>';
    return;
  }

  list.innerHTML = indicators.map((ind, i) => `
    <div class="indicator-card ${ind.severity}" id="ind-${i}" onclick="toggleIndicator(${i}, '${escHtml(ind.name)}', '${ind.severity}', \`${escHtml(ind.tip)}\`)">
      <div class="indicator-header">
        <span class="indicator-name">${escHtml(ind.name)}</span>
        <span class="badge badge-${ind.severity}">${ind.severity}</span>
        <span class="expand-icon">▼</span>
      </div>
      <div class="indicator-tip" id="tip-${i}">${escHtml(ind.tip)}</div>
    </div>
  `).join('');
}

function toggleIndicator(i, name, severity, tip) {
  const card = document.getElementById(`ind-${i}`);
  const tipEl = document.getElementById(`tip-${i}`);
  if (!card || !tipEl) return;
  const isOpen = card.classList.contains('open');
  if (isOpen) {
    card.classList.remove('open');
    tipEl.classList.remove('open');
  } else {
    card.classList.add('open');
    tipEl.classList.add('open');
  }
}

function setLoading(on) {
  analyzeBtn.disabled = on;
  const btnText = document.getElementById('btn-text');
  const spinner = document.getElementById('btn-spinner');
  if (btnText) btnText.textContent = on ? 'Analysing...' : 'Run Analysis';
  if (spinner) spinner.style.display = on ? 'block' : 'none';
}

function showError(msg) {
  const el = document.getElementById('error-box');
  if (el) {
    el.textContent = `⚠ Error: ${msg}`;
    el.style.display = 'block';
    setTimeout(() => { el.style.display = 'none'; }, 6000);
  } else {
    alert(`Error: ${msg}`);
  }
}

function shake(el) {
  el.style.animation = 'shake .4s ease';
  setTimeout(() => { el.style.animation = ''; }, 500);
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}

const exampleBtns = document.querySelectorAll('[data-example]');
exampleBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    const mode = btn.dataset.mode;
    const val  = btn.dataset.example;

    tabBtns.forEach(b => {
      b.classList.toggle('active', b.dataset.mode === mode);
    });
    currentMode = mode;
    urlInput.style.display   = mode === 'url'   ? 'block' : 'none';
    emailInput.style.display = mode === 'email' ? 'block' : 'none';

    if (mode === 'url') {
      document.getElementById('url-field').value = val;
    } else {
      document.getElementById('email-field').value = val;
    }
  });
});

const style = document.createElement('style');
style.textContent = `@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-5px)}80%{transform:translateX(5px)}}`;
document.head.appendChild(style);

window.toggleIndicator = toggleIndicator;