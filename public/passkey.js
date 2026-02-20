/* global window, document, navigator, fetch, btoa, atob, HTMLElement */

(() => {
    function byId(id) {
        return document.getElementById(id);
    }

    function supportsPasskey() {
        return Boolean(window.PublicKeyCredential && navigator.credentials);
    }

    function toBase64Url(value) {
        const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        let binary = '';
        for (const byte of bytes) {
            binary += String.fromCharCode(byte);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function fromBase64Url(value) {
        const padded = value.padEnd(Math.ceil(value.length / 4) * 4, '=').replace(/-/g, '+').replace(/_/g, '/');
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function creationOptionsFromJSON(options) {
        if (window.PublicKeyCredential && typeof window.PublicKeyCredential.parseCreationOptionsFromJSON === 'function') {
            return window.PublicKeyCredential.parseCreationOptionsFromJSON(options);
        }

        const parsed = JSON.parse(JSON.stringify(options));
        parsed.challenge = fromBase64Url(options.challenge);
        parsed.user.id = fromBase64Url(options.user.id);
        if (Array.isArray(parsed.excludeCredentials)) {
            parsed.excludeCredentials = parsed.excludeCredentials.map((cred) => ({
                ...cred,
                id: fromBase64Url(cred.id),
            }));
        }
        return parsed;
    }

    function requestOptionsFromJSON(options) {
        if (window.PublicKeyCredential && typeof window.PublicKeyCredential.parseRequestOptionsFromJSON === 'function') {
            return window.PublicKeyCredential.parseRequestOptionsFromJSON(options);
        }

        const parsed = JSON.parse(JSON.stringify(options));
        parsed.challenge = fromBase64Url(options.challenge);
        if (Array.isArray(parsed.allowCredentials)) {
            parsed.allowCredentials = parsed.allowCredentials.map((cred) => ({
                ...cred,
                id: fromBase64Url(cred.id),
            }));
        }
        return parsed;
    }

    function registrationCredentialToJSON(credential) {
        const response = credential.response;
        return {
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            response: {
                clientDataJSON: toBase64Url(response.clientDataJSON),
                attestationObject: toBase64Url(response.attestationObject),
                transports: typeof response.getTransports === 'function' ? response.getTransports() : [],
            },
            type: credential.type,
            clientExtensionResults: typeof credential.getClientExtensionResults === 'function'
                ? credential.getClientExtensionResults()
                : {},
            authenticatorAttachment: credential.authenticatorAttachment || undefined,
        };
    }

    function authenticationCredentialToJSON(credential) {
        const response = credential.response;
        return {
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            response: {
                clientDataJSON: toBase64Url(response.clientDataJSON),
                authenticatorData: toBase64Url(response.authenticatorData),
                signature: toBase64Url(response.signature),
                userHandle: response.userHandle ? toBase64Url(response.userHandle) : undefined,
            },
            type: credential.type,
            clientExtensionResults: typeof credential.getClientExtensionResults === 'function'
                ? credential.getClientExtensionResults()
                : {},
            authenticatorAttachment: credential.authenticatorAttachment || undefined,
        };
    }

    async function postJson(url, payload) {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(payload),
        });

        let data = {};
        try {
            data = await response.json();
        } catch {
            // ignore non-json response
        }

        if (!response.ok) {
            const message = typeof data.error === 'string' ? data.error : `HTTP ${response.status}`;
            throw new Error(message);
        }

        return data;
    }

    async function getJson(url) {
        const response = await fetch(url, { credentials: 'include' });
        let data = {};
        try {
            data = await response.json();
        } catch {
            // ignore non-json response
        }

        if (!response.ok) {
            const message = typeof data.error === 'string' ? data.error : `HTTP ${response.status}`;
            throw new Error(message);
        }
        return data;
    }

    function setMessage(element, message, isError) {
        if (!element) return;
        element.textContent = message;
        element.style.color = isError ? '#b91c1c' : '#6b7280';
    }

    function getLoginUsername() {
        const passkeyUsername = byId('passkey-login-username');
        if (passkeyUsername && typeof passkeyUsername.value === 'string' && passkeyUsername.value.trim()) {
            return passkeyUsername.value.trim();
        }

        const formUsername = document.querySelector('input[name="username"]');
        if (formUsername && typeof formUsername.value === 'string' && formUsername.value.trim()) {
            return formUsername.value.trim();
        }

        return '';
    }

    async function initPasskeyLogin() {
        const button = byId('passkey-login-button');
        if (!button) return;

        const redirectInput = byId('passkey-login-redirect-uri');
        const message = byId('passkey-login-message');

        if (!supportsPasskey()) {
            button.disabled = true;
            setMessage(message, 'Passkeys werden auf diesem Gerät/Browser nicht unterstützt.', true);
            return;
        }

        button.addEventListener('click', async () => {
            const username = getLoginUsername();
            const redirectUri = redirectInput && typeof redirectInput.value === 'string' ? redirectInput.value : '/';
            button.disabled = true;
            setMessage(message, username ? 'Passkey-Anfrage wird gestartet...' : 'Passkey-Discovery wird gestartet...', false);

            try {
                const optionsPayload = { redirect_uri: redirectUri };
                if (username) {
                    optionsPayload.username = username;
                }

                const optionsResponse = await postJson('/passkey/auth/options', optionsPayload);

                const publicKey = requestOptionsFromJSON(optionsResponse.options);
                const assertion = await navigator.credentials.get({ publicKey });
                if (!assertion) {
                    throw new Error('Keine Passkey-Antwort erhalten.');
                }

                const credential = authenticationCredentialToJSON(assertion);
                const verifyResponse = await postJson('/passkey/auth/verify', {
                    flowId: optionsResponse.flowId,
                    redirect_uri: redirectUri,
                    credential,
                });

                const target = typeof verifyResponse.redirectTo === 'string' ? verifyResponse.redirectTo : '/';
                window.location.assign(target);
            } catch (error) {
                setMessage(message, error instanceof Error ? error.message : 'Passkey-Login fehlgeschlagen.', true);
            } finally {
                button.disabled = false;
            }
        });
    }

    function passkeyStorageText(credential) {
        if (credential && credential.backedUp === true) {
            return 'Auf mehreren eigenen Geräten verfügbar.';
        }
        return 'Auf diesem Gerät gespeichert.';
    }

    function credentialRowHtml(credential, index) {
        const createdAt = new Date(credential.createdAt).toLocaleString('de-DE');
        const lastUsedAt = new Date(credential.lastUsedAt).toLocaleString('de-DE');
        const title = typeof index === 'number' ? `Passkey ${index}` : 'Passkey';
        const storageText = passkeyStorageText(credential);

        return `
            <div class="passkey-item">
                <div><strong>${title}</strong></div>
                <div class="meta">Eingerichtet am: ${createdAt}</div>
                <div class="meta">Zuletzt genutzt: ${lastUsedAt}</div>
                <div class="meta">${storageText}</div>
                <button type="button" class="button--small button--danger" data-credential-id="${credential.credentialId}">Passkey entfernen</button>
            </div>
        `;
    }

    async function refreshCredentialList() {
        const list = byId('passkey-credential-list');
        if (!list) return;

        try {
            const data = await getJson('/passkey/credentials');
            const credentials = Array.isArray(data.credentials) ? data.credentials : [];
            if (credentials.length === 0) {
                list.innerHTML = '<p class="meta">Noch kein Passkey registriert.</p>';
                return;
            }
            list.innerHTML = credentials.map((credential, index) => credentialRowHtml(credential, index + 1)).join('');
        } catch (error) {
            list.innerHTML = `<p class="meta" style="color:#b91c1c;">${error instanceof Error ? error.message : 'Fehler beim Laden.'}</p>`;
        }
    }

    async function initPasskeyRegistration() {
        const button = byId('passkey-register-button');
        if (!button) return;

        const message = byId('passkey-register-message');
        const list = byId('passkey-credential-list');
        const redirectInput = byId('passkey-post-register-redirect-uri');
        const autoRedirectInput = byId('passkey-auto-redirect-after-register');

        if (!supportsPasskey()) {
            button.disabled = true;
            setMessage(message, 'Passkeys werden auf diesem Gerät/Browser nicht unterstützt.', true);
            if (list) {
                list.innerHTML = '<p class="meta">Passkeys nicht verfügbar.</p>';
            }
            return;
        }

        button.addEventListener('click', async () => {
            button.disabled = true;
            setMessage(message, 'Passkey-Registrierung wird gestartet...', false);

            try {
                const optionsResponse = await postJson('/passkey/register/options', {});
                const publicKey = creationOptionsFromJSON(optionsResponse.options);
                const credential = await navigator.credentials.create({ publicKey });
                if (!credential) {
                    throw new Error('Keine Passkey-Antwort erhalten.');
                }

                await postJson('/passkey/register/verify', {
                    flowId: optionsResponse.flowId,
                    credential: registrationCredentialToJSON(credential),
                });

                setMessage(message, 'Passkey erfolgreich registriert.', false);
                await refreshCredentialList();

                const shouldAutoRedirect = autoRedirectInput && autoRedirectInput.value === '1';
                const redirectTo = redirectInput && typeof redirectInput.value === 'string' ? redirectInput.value : '';
                if (shouldAutoRedirect && redirectTo) {
                    setMessage(message, 'Passkey erfolgreich registriert. Weiterleitung...', false);
                    window.setTimeout(() => {
                        window.location.assign(redirectTo);
                    }, 350);
                }
            } catch (error) {
                setMessage(message, error instanceof Error ? error.message : 'Passkey-Registrierung fehlgeschlagen.', true);
            } finally {
                button.disabled = false;
            }
        });

        if (list) {
            list.addEventListener('click', async (event) => {
                const target = event.target;
                if (!(target instanceof HTMLElement)) return;
                const credentialId = target.dataset.credentialId;
                if (!credentialId) return;

                target.setAttribute('disabled', 'true');
                try {
                    await postJson('/passkey/credentials/delete', { credentialId });
                    await refreshCredentialList();
                    setMessage(message, 'Passkey gelöscht.', false);
                } catch (error) {
                    setMessage(message, error instanceof Error ? error.message : 'Löschen fehlgeschlagen.', true);
                } finally {
                    target.removeAttribute('disabled');
                }
            });
            await refreshCredentialList();
        }
    }

    window.addEventListener('DOMContentLoaded', () => {
        void initPasskeyLogin();
        void initPasskeyRegistration();
    });
})();
