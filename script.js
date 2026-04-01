/**
 * NaijaEarn Hub - Shared JavaScript
 * Handles: theme toggle, scroll reveal, global UI utilities
 */

// ===== THEME TOGGLE =====
(function initTheme() {
  const saved = localStorage.getItem('naija_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeIcon(saved);
})();

function updateThemeIcon(theme) {
  const btn = document.getElementById('themeToggle');
  if (btn) btn.textContent = theme === 'dark' ? '🌙' : '☀️';
}

document.addEventListener('DOMContentLoaded', () => {
  const themeBtn = document.getElementById('themeToggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('naija_theme', next);
      updateThemeIcon(next);
    });
  }

  // ===== SCROLL REVEAL =====
  const reveals = document.querySelectorAll('.reveal');
  if (reveals.length) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

    reveals.forEach(el => observer.observe(el));
  }

  // ===== CLOSE MODALS ON OVERLAY CLICK =====
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.classList.remove('active');
      }
    });
  });

  // ===== PREVENT ZOOM ON INPUT FOCUS (iOS/Android) =====
  const inputs = document.querySelectorAll('input, select, textarea');
  inputs.forEach(input => {
    if (parseInt(getComputedStyle(input).fontSize) < 16) {
      input.style.fontSize = '16px';
    }
  });
});
