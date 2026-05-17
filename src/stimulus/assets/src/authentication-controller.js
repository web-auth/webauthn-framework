'use strict';

import {
    browserSupportsWebAuthn,
    browserSupportsWebAuthnAutofill,
    startAuthentication,
    WebAuthnAbortService,
    WebAuthnError,
    platformAuthenticatorIsAvailable,
} from '@simplewebauthn/browser';
import BaseController from './base-controller.js';

/**
 * @typedef {import('@simplewebauthn/browser').PublicKeyCredentialRequestOptionsJSON} PublicKeyCredentialRequestOptionsJSON
 * @typedef {import('@simplewebauthn/browser').AuthenticationResponseJSON} AuthenticationResponseJSON
 * @typedef {import('@simplewebauthn/browser').StartAuthenticationOpts} StartAuthenticationOpts
 */

/**
 * Stimulus controller for WebAuthn authentication (sign-in).
 *
 * Usage:
 * ```html
 * <form data-controller="webauthn--authentication"
 *       data-webauthn--authentication-options-url-value="/auth/options"
 *       data-webauthn--authentication-result-url-value="/auth/verify"
 *       data-webauthn--authentication-conditional-ui-value="true"
 *       data-action="submit->webauthn--authentication#authenticate">
 *   <input type="text" name="username" autocomplete="username webauthn" data-webauthn--authentication-target="username">
 *   <input type="hidden" data-webauthn--authentication-target="result">
 *   <button type="submit">Sign In</button>
 * </form>
 * ```
 */
export default class AuthenticationController extends BaseController {
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
        this._dispatchEvent('webauthn:authentication:connect', {
            optionsUrl: this.optionsUrlValue,
            resultUrl: this.resultUrlValue,
            supportsPlatformAuthenticator: await platformAuthenticatorIsAvailable(),
        });

        if (!this.conditionalUiValue) {
            return;
        }

        const supportsAutofill = await browserSupportsWebAuthnAutofill();
        if (supportsAutofill) {
            await this._startAuthenticationWithConditionalUi();
        }
    }

    disconnect() {
        // Cancel any pending WebAuthn operations when the controller is disconnected
        // (e.g., when navigating away from the page)
        WebAuthnAbortService.cancelCeremony();
    }

    /**
     * Authenticate the user via WebAuthn.
     *
     * @param {Event} event Form submit event.
     * @returns {Promise<void>}
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
     * Start authentication with conditional UI (browser autofill).
     *
     * @private
     * @returns {Promise<void>}
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
     * Start authentication process.
     *
     * @private
     * @param {Partial<StartAuthenticationOpts>} [options] Additional options for startAuthentication.
     * @returns {Promise<void>}
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
     * Process authentication with WebAuthn.
     *
     * @private
     * @param {PublicKeyCredentialRequestOptionsJSON} credentialRequestOptions WebAuthn credential request options.
     * @param {Partial<StartAuthenticationOpts>} [startAuthenticationOptions] Options for startAuthentication call.
     * @returns {Promise<void>}
     */
    async _processAuthentication(credentialRequestOptions, startAuthenticationOptions = {}) {
        try {
            const processedOptions = this._processExtensionsInput(credentialRequestOptions);

            let credential = await startAuthentication({
                optionsJSON: processedOptions,
                ...startAuthenticationOptions,
            });

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
}
