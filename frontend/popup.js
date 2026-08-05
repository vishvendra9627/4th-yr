const overlay = document.getElementById('popup-overlay');
const popupTitle = document.getElementById('popup-title');
const popupSeverity = document.getElementById('popup-severity');
const popupBody = document.getElementById('popup-body');

function cleanText(text) {
  return String(text)
    .replace(/-/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function openPopup(name, severity, tip) {

  const labels = { high: 'High risk', medium: 'Medium risk', low: 'Low risk' };
  const classes = { high: 'badge-high', medium: 'badge-medium', low: 'badge-low' };

  popupTitle.textContent = cleanText(name);
  popupSeverity.textContent = labels[severity] || cleanText(severity);
  popupSeverity.className = `badge popup-severity ${classes[severity] || ''}`;
  popupBody.textContent = cleanText(tip);

  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closePopup() {
  overlay.classList.remove('open');
  document.body.style.overflow = '';
}

if (overlay) {
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closePopup();
  });
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closePopup();
});

window.openPopup = openPopup;
window.closePopup = closePopup;
