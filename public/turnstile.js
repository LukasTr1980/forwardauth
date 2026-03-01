/* global window, document */

(() => {
    const STATUS_WAITING = 'waiting';
    const STATUS_SOLVED = 'solved';
    const STATUS_ERROR = 'error';

    function readTurnstileToken(form) {
        const tokenInput = form.querySelector('input[name="cf-turnstile-response"]');
        if (!tokenInput || typeof tokenInput.value !== 'string') {
            return '';
        }
        return tokenInput.value.trim();
    }

    function setStatus(statusNode, submitButton, status) {
        if (submitButton) {
            submitButton.disabled = status !== STATUS_SOLVED;
        }

        if (!statusNode) return;

        statusNode.classList.remove('meta--error', 'meta--success');
        if (status === STATUS_SOLVED) {
            statusNode.textContent = '';
            return;
        }

        if (status === STATUS_ERROR) {
            statusNode.textContent = 'Sicherheitsprüfung fehlgeschlagen. Bitte kurz warten oder Seite neu laden.';
            statusNode.classList.add('meta--error');
            return;
        }

        statusNode.textContent = 'Sicherheitsprüfung läuft. Bitte kurz warten.';
    }

    function syncStatusFromToken(form, statusNode, submitButton) {
        const hasToken = readTurnstileToken(form).length > 0;
        setStatus(statusNode, submitButton, hasToken ? STATUS_SOLVED : STATUS_WAITING);
    }

    function initForgotPasswordTurnstileGate() {
        const form = document.querySelector('form[action$="/auth/forgot-password"]');
        if (!form || form.dataset.turnstileRequired !== '1') {
            return;
        }

        const submitButton = document.getElementById('forgot-submit-button');
        const statusNode = document.getElementById('forgot-turnstile-status');

        syncStatusFromToken(form, statusNode, submitButton);

        window.onForgotPasswordTurnstileSuccess = (token) => {
            const hasToken = typeof token === 'string' && token.trim().length > 0;
            setStatus(statusNode, submitButton, hasToken ? STATUS_SOLVED : STATUS_WAITING);
        };
        window.onForgotPasswordTurnstileExpired = () => {
            setStatus(statusNode, submitButton, STATUS_WAITING);
        };
        window.onForgotPasswordTurnstileError = () => {
            setStatus(statusNode, submitButton, STATUS_ERROR);
        };

        const syncInterval = window.setInterval(() => {
            syncStatusFromToken(form, statusNode, submitButton);
        }, 400);
        window.addEventListener('beforeunload', () => {
            window.clearInterval(syncInterval);
        }, { once: true });

        form.addEventListener('submit', (event) => {
            if (readTurnstileToken(form)) {
                return;
            }
            setStatus(statusNode, submitButton, STATUS_WAITING);
            event.preventDefault();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initForgotPasswordTurnstileGate, { once: true });
    } else {
        initForgotPasswordTurnstileGate();
    }
})();
