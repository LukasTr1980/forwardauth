/* global window, document */

(() => {
    function readTurnstileToken(form) {
        const tokenInput = form.querySelector('input[name="cf-turnstile-response"]');
        if (!tokenInput || typeof tokenInput.value !== 'string') {
            return '';
        }
        return tokenInput.value.trim();
    }

    function setStatus(statusNode, submitButton, solved) {
        if (submitButton) {
            submitButton.disabled = !solved;
        }

        if (!statusNode) return;

        statusNode.classList.remove('meta--error', 'meta--success');
        if (solved) {
            statusNode.textContent = 'Sicherheitsprüfung erfolgreich. Sie können jetzt absenden.';
            statusNode.classList.add('meta--success');
            return;
        }

        statusNode.textContent = 'Bitte erst die Sicherheitsprüfung abschließen.';
        statusNode.classList.add('meta--error');
    }

    function initForgotPasswordTurnstileGate() {
        const form = document.querySelector('form[action$="/auth/forgot-password"]');
        if (!form || form.dataset.turnstileRequired !== '1') {
            return;
        }

        const submitButton = document.getElementById('forgot-submit-button');
        const statusNode = document.getElementById('forgot-turnstile-status');

        setStatus(statusNode, submitButton, false);

        window.onForgotPasswordTurnstileSuccess = (token) => {
            const solved = typeof token === 'string' && token.trim().length > 0;
            setStatus(statusNode, submitButton, solved);
        };
        window.onForgotPasswordTurnstileExpired = () => {
            setStatus(statusNode, submitButton, false);
        };
        window.onForgotPasswordTurnstileError = () => {
            setStatus(statusNode, submitButton, false);
        };

        form.addEventListener('submit', (event) => {
            if (readTurnstileToken(form)) {
                return;
            }
            setStatus(statusNode, submitButton, false);
            event.preventDefault();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initForgotPasswordTurnstileGate, { once: true });
    } else {
        initForgotPasswordTurnstileGate();
    }
})();
