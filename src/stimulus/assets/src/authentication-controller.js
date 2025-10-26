'use strict';

import {
    browserSupportsWebAuthn,
    browserSupportsWebAuthnAutofill,
    startAuthentication,
    WebAuthnAbortService,
    WebAuthnError,
} from '@simplewebauthn/browser';
import BaseController from './base-controller.js';

/**
 * Stimulus controller for WebAuthn authentication (sign-in)
 *
 * Usage:
 * <form data-controller="webauthn--authentication"
 *       data-webauthn--authentication-options-url-value="/auth/options"
 *       data-webauthn--authentication-result-url-value="/auth/verify"
 *       data-action="submit->webauthn--authentication#authenticate">
 *   <input type="text" name="username" data-webauthn--authentication-target="username">
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
 * @property {boolean} useResultTargetValue - Whether to use result target for form submission
 * @property {boolean} hasUseResultTargetValue - Whether useResultTarget value is set
 * @property {string} successRedirectUriValue - URI to redirect to on success
 * @property {boolean} hasSuccessRedirectUriValue - Whether successRedirectUri value is set
 * @property {boolean} useBrowserAutofillValue - Whether to enable browser autofill
 * @property {boolean} hasUseBrowserAutofillValue - Whether useBrowserAutofill value is set
 */
export default class extends BaseController {
    static targets = ['username', 'userVerification', 'result'];

    static values = {
        ...BaseController.values,
        optionsUrl: { type: String, default: '/authentication/options' },
        resultUrl: { type: String, default: '/authentication/verify' },
        useResultTarget: { type: Boolean, default: false },
        successRedirectUri: String,
        useBrowserAutofill: { type: Boolean, default: false },
    };

    async connect() {
        this._dispatchEvent('webauthn:authentication:connect', {
            optionsUrl: this.optionsUrlValue,
            resultUrl: this.resultUrlValue,
        });

        if (!this.useBrowserAutofillValue) {
            return;
        }

        const supportsAutofill = await browserSupportsWebAuthnAutofill();
        if (supportsAutofill) {
            await this._startAuthenticationWithAutofill();
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
     * Start authentication with browser autofill
     * @private
     */
    async _startAuthenticationWithAutofill() {
        const options = await this._fetchOptions(this.optionsUrlValue, {}, 'webauthn:authentication');
        if (!options) {
            return;
        }

        await this._processAuthentication(options, true);
    }

    /**
     * Start authentication process
     * @private
     * @param {boolean} useBrowserAutofill - Whether to use browser autofill
     */
    async _startAuthentication(useBrowserAutofill) {
        const formData = this._getFormData([
            { name: 'username', targetName: 'username' },
            { name: 'userVerification', targetName: 'userVerification' },
        ]);

        if (formData === null) {
            return;
        }

        const options = await this._fetchOptions(this.optionsUrlValue, formData, 'webauthn:authentication');
        if (!options) {
            return;
        }

        await this._processAuthentication(options, useBrowserAutofill);
    }

    /**
     * Process authentication with WebAuthn
     * @private
     * @param {Object} options - WebAuthn credential request options
     * @param {boolean} useBrowserAutofill - Whether to use browser autofill
     */
    async _processAuthentication(options, useBrowserAutofill) {
        try {
            const processedOptions = this._processExtensionsInput(options);

            let credential = await startAuthentication({
                optionsJSON: processedOptions,
                useBrowserAutofill,
            });

            credential = this._processExtensionsOutput(credential);
            this._dispatchEvent('webauthn:authentication:credential', { credential });

            // Submit via form if using result target
            if (this.useResultTargetValue && this.hasResultTarget) {
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
