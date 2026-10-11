(() => {
  'use strict';

  // Form validation
  function initValidation() {
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
      if (form.dataset.validationBound) return;
      form.dataset.validationBound = 'true';
      form.addEventListener('submit', event => {
        if (!form.checkValidity()) {
          event.preventDefault();
          event.stopPropagation();
        }
        form.classList.add('was-validated');
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initValidation);
  } else {
    initValidation();
  }

  // Password visibility toggle using robust event delegation
  document.addEventListener('click', event => {
    const btn = event.target.closest('.toggle-password');
    if (!btn) return;

    event.preventDefault();
    const targetId = btn.getAttribute('data-target');
    if (!targetId) return;

    const input = document.getElementById(targetId);
    if (!input) return;

    const icon = btn.querySelector('i');
    if (input.type === 'password') {
      input.type = 'text';
      if (icon) {
        icon.classList.remove('bi-eye-slash');
        icon.classList.add('bi-eye');
      }
      btn.setAttribute('aria-label', 'Hide password');
    } else {
      input.type = 'password';
      if (icon) {
        icon.classList.remove('bi-eye');
        icon.classList.add('bi-eye-slash');
      }
      btn.setAttribute('aria-label', 'Show password');
    }
  });
})();