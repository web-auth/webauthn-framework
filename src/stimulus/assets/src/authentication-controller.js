'use strict';

import {
    base64URLStringToBuffer,
    browserSupportsWebAuthn,
    startAuthentication,
    WebAuthnAbortService,
    WebAuthnError,
    platformAuthenticatorIsAvailable,
} from '@simplewebauthn/browser';
import BaseController from './base-controller.js';

/**
 * Allowed `CredentialUiMode` values per the W3C Credential Management spec
 * (editor's draft, §2.3.3). Kept narrow on purpose: forwarding an unknown
 * value to `navigator.credentials.get()` would silently degrade to default
 * UA behaviour, which is harder to debug than a controller-side rejection.
 *
 * @see https://w3c.github.io/webappsec-credential-management/#enumdef-credentialuimode
 */
const ALLOWED_UI_MODES = ['auto', 'immediate'];

/**
 * Stimulus controller for WebAuthn authentication (sign-in)
 *
 * Usage:
 * <form data-controller="webauthn--authentication"
 *       data-webauthn--authentication-options-url-value="/auth/options"
 *       data-webauthn--authentication-result-url-value="/auth/verify"
 *       data-webauthn--authentication-conditional-ui-value="true"
 *       data-action="submit->webauthn--authentication#authenticate">
 *   <input type="text" name="username" autocomplete="username webauthn" data-webauthn--authentication-target="username">
 *   <input type="hidden" data-webauthn--authentication-target="result">
 *   <button type="submit">Sign In</button>
 * </form>
 *
 * @property {HTMLInputElement} usernameTarget - Username input element
 * @property {boolean} hasUsernameTarget - Whether username target exists
 * @property {HTMLSelectElement} userVerificationTarget - User verification input element
 * @property {boolean} hasUserVerificationTarget - Whether userVerification target exists
 * @property {HTMLInputElement} resultTarget - Result hidden input element
 * @property {boolean} hasResultTarget - Whether result target exists
 *
 * @property {string} optionsUrlValue - URL to fetch authentication options from
 * @property {boolean} hasOptionsUrlValue - Whether optionsUrl value is set
 * @property {string} resultUrlValue - URL to verify authentication result at
 * @property {boolean} hasResultUrlValue - Whether resultUrl value is set
 * @property {boolean} submitViaFormValue - Whether to submit credential via form instead of API
 * @property {boolean} hasSubmitViaFormValue - Whether submitViaForm value is set
 * @property {string} successRedirectUriValue - URI to redirect to on success
 * @property {boolean} hasSuccessRedirectUriValue - Whether successRedirectUri value is set
 * @property {boolean} conditionalUiValue - Whether to enable conditional UI (browser autofill)
 * @property {boolean} hasConditionalUiValue - Whether conditionalUi value is set
 * @property {boolean} verifyAutofillInputValue - Whether to verify autofill input element exists
 * @property {boolean} hasVerifyAutofillInputValue - Whether verifyAutofillInput value is set
 */
export default class extends BaseController {
    static targets = ['username', 'userVerification', 'result'];

    static values = {
        ...BaseController.values,
        optionsUrl: { type: String, default: '/authentication/options' },
        resultUrl: { type: String, default: '/authentication/verify' },
        submitViaForm: { type: Boolean, default: false },
        successRedirectUri: String,
        conditionalUi: { type: Boolean, default: false },
        verifyAutofillInput: { type: Boolean, default: true },
    };

    async connect() {
        const capabilities = await this._getClientCapabilities();
        this._dispatchEvent('webauthn:authentication:connect', {
            optionsUrl: this.optionsUrlValue,
            resultUrl: this.resultUrlValue,
            supportsPlatformAuthenticator: await platformAuthenticatorIsAvailable(),
            capabilities,
        });

        if (!this.conditionalUiValue) {
            return;
        }

        // WebAuthn L3 §5.1.7: prefer the native capability map over the
        // deprecated isConditionalMediationAvailable / browserSupportsWebAuthnAutofill
        // wrapper. _getClientCapabilities falls back to the legacy detector
        // on user agents that have not shipped getClientCapabilities yet.
        if (capabilities.conditionalGet === true) {
            await this._startAuthenticationWithConditionalUi();
        }
    }

    disconnect() {
        // Cancel any pending WebAuthn operations when the controller is disconnected
        // (e.g., when navigating away from the page)
        WebAuthnAbortService.cancelCeremony();
    }

    /**
     * Authenticate user via WebAuthn
     * @param {Event} event - Form submit event
     */
    async authenticate(event) {
        event.preventDefault();

        if (!browserSupportsWebAuthn()) {
            this._dispatchEvent('webauthn:unsupported', {});
            return;
        }

        await this._startAuthentication(false);
    }

    /**
     * Start authentication with conditional UI (browser autofill)
     * @private
     */
    async _startAuthenticationWithConditionalUi() {
        const options = await this._fetchOptions(this.optionsUrlValue, {}, 'webauthn:authentication');
        if (!options) {
            return;
        }

        await this._processAuthentication(options, {
            useBrowserAutofill: true,
            verifyBrowserAutofillInput: this.verifyAutofillInputValue,
        });
    }

    /**
     * Start authentication process
     * @private
     * @param {Object} options - Additional options for startAuthentication
     */
    async _startAuthentication(options = {}) {
        const formData = this._getFormData([
            { name: 'username', targetName: 'username' },
            { name: 'userVerification', targetName: 'userVerification' },
        ]);

        if (formData === null) {
            return;
        }

        const webauthnOptions = await this._fetchOptions(this.optionsUrlValue, formData, 'webauthn:authentication');
        if (!webauthnOptions) {
            return;
        }

        await this._processAuthentication(webauthnOptions, options);
    }

    /**
     * Process authentication with WebAuthn
     * @private
     * @param {Object} credentialRequestOptions - WebAuthn credential request options
     * @param {Object} startAuthenticationOptions - Options for startAuthentication call
     */
    async _processAuthentication(credentialRequestOptions, startAuthenticationOptions = {}) {
        try {
            const processedOptions = this._processExtensionsInput(credentialRequestOptions);
            const uiMode = this._extractUiMode(processedOptions);

            let credential;
            if (uiMode === 'immediate') {
                // SimpleWebAuthn 13.x has no native `uiMode` support yet, so
                // we call `navigator.credentials.get()` directly and rely on
                // PublicKeyCredential.toJSON() for the response shape.
                credential = await this._getCredentialWithUiMode(processedOptions, uiMode);
            } else {
                credential = await startAuthentication({
                    optionsJSON: processedOptions,
                    ...startAuthenticationOptions,
                });
            }

            credential = this._processExtensionsOutput(credential);
            this._dispatchEvent('webauthn:authentication:credential', { credential });

            // Submit via form if using result target
            if (this.submitViaFormValue && this.hasResultTarget) {
                this.resultTarget.value = JSON.stringify(credential);
                this.element.submit();
                return;
            }

            // Otherwise, verify via API
            const verificationResult = await this._verifyCredential(
                this.resultUrlValue,
                credential,
                'webauthn:authentication'
            );

            if (verificationResult && this.hasSuccessRedirectUriValue) {
                window.location.replace(this.successRedirectUriValue);
            }
        } catch (error) {
            // Check if this is a WebAuthn-specific error
            if (error instanceof WebAuthnError) {
                this._dispatchEvent('webauthn:authentication:error', {
                    error,
                    code: error.code,
                    name: error.name,
                });
            } else {
                this._dispatchEvent('webauthn:authentication:error', { error });
            }
        }
    }

    /**
     * Pop `uiMode` off the options JSON and validate it.
     * @private
     * @param {Object} optionsJSON - WebAuthn credential request options (mutated)
     * @returns {string|null} A validated `CredentialUiMode` value, or null if absent
     */
    _extractUiMode(optionsJSON) {
        if (!optionsJSON || typeof optionsJSON.uiMode === 'undefined' || optionsJSON.uiMode === null) {
            return null;
        }
        const uiMode = optionsJSON.uiMode;
        delete optionsJSON.uiMode;

        if (typeof uiMode !== 'string' || !ALLOWED_UI_MODES.includes(uiMode)) {
            throw new TypeError(`Invalid uiMode "${uiMode}". Allowed values: ${ALLOWED_UI_MODES.join(', ')}.`);
        }
        return uiMode;
    }

    /**
     * Call `navigator.credentials.get()` directly with a `uiMode` option.
     * Used when SimpleWebAuthn does not natively forward the option.
     * @private
     * @param {Object} optionsJSON - WebAuthn credential request options (uiMode already removed)
     * @param {string} uiMode - Validated CredentialUiMode value
     * @returns {Promise<Object>} JSON-serialised credential
     */
    async _getCredentialWithUiMode(optionsJSON, uiMode) {
        const publicKey = {
            ...optionsJSON,
            challenge: base64URLStringToBuffer(optionsJSON.challenge),
        };
        if (Array.isArray(optionsJSON.allowCredentials)) {
            publicKey.allowCredentials = optionsJSON.allowCredentials.map((descriptor) => ({
                ...descriptor,
                id: base64URLStringToBuffer(descriptor.id),
            }));
        }

        const credential = await navigator.credentials.get({
            publicKey,
            uiMode,
            signal: WebAuthnAbortService.createNewAbortSignal(),
        });

        if (credential === null) {
            throw new Error('navigator.credentials.get() returned null');
        }
        return credential.toJSON();
    }
}
