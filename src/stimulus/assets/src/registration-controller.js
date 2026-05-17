'use strict';

import {
    browserSupportsWebAuthn,
    startRegistration,
    WebAuthnAbortService,
    WebAuthnError,
    platformAuthenticatorIsAvailable,
} from '@simplewebauthn/browser';
import BaseController from './base-controller.js';

/**
 * @typedef {import('@simplewebauthn/browser').PublicKeyCredentialCreationOptionsJSON} PublicKeyCredentialCreationOptionsJSON
 * @typedef {import('@simplewebauthn/browser').RegistrationResponseJSON} RegistrationResponseJSON
 */

/**
 * Stimulus controller for WebAuthn registration (credential creation).
 *
 * Usage:
 * ```html
 * <form data-controller="webauthn--registration"
 *       data-webauthn--registration-options-url-value="/register/options"
 *       data-webauthn--registration-result-url-value="/register/verify"
 *       data-action="submit->webauthn--registration#register">
 *   <input type="text" name="username" data-webauthn--registration-target="username">
 *   <select name="attestation" data-webauthn--registration-target="attestation">
 *     <option value="none">None</option>
 *     <option value="direct">Direct</option>
 *   </select>
 *   <input type="hidden" data-webauthn--registration-target="result">
 *   <button type="submit">Register</button>
 * </form>
 * ```
 */
export default class RegistrationController extends BaseController {
    static targets = [
        'username',
        'attestation',
        'residentKey',
        'userVerification',
        'authenticatorAttachment',
        'result',
    ];

    static values = {
        ...BaseController.values,
        optionsUrl: { type: String, default: '/registration/options' },
        resultUrl: { type: String, default: '/registration/verify' },
        submitViaForm: { type: Boolean, default: false },
        successRedirectUri: String,
        autoRegister: { type: Boolean, default: false },
    };

    async connect() {
        this._dispatchEvent('webauthn:registration:connect', {
            optionsUrl: this.optionsUrlValue,
            resultUrl: this.resultUrlValue,
            supportsPlatformAuthenticator: await platformAuthenticatorIsAvailable(),
        });
    }

    disconnect() {
        // Cancel any pending WebAuthn operations when the controller is disconnected
        // (e.g., when navigating away from the page)
        WebAuthnAbortService.cancelCeremony();
    }

    /**
     * Register a new WebAuthn credential.
     *
     * @param {Event} event Form submit event.
     * @returns {Promise<void>}
     */
    async register(event) {
        event.preventDefault();

        if (!browserSupportsWebAuthn()) {
            this._dispatchEvent('webauthn:unsupported', {});
            return;
        }

        await this._startRegistration();
    }

    /**
     * Start registration process.
     *
     * @private
     * @returns {Promise<void>}
     */
    async _startRegistration() {
        const formData = this._getFormData([
            { name: 'username', targetName: 'username' },
            { name: 'attestation', targetName: 'attestation' },
            { name: 'residentKey', targetName: 'residentKey' },
            { name: 'userVerification', targetName: 'userVerification' },
            { name: 'authenticatorAttachment', targetName: 'authenticatorAttachment' },
        ]);

        if (formData === null) {
            return;
        }

        const options = await this._fetchOptions(this.optionsUrlValue, formData, 'webauthn:registration');
        if (!options) {
            return;
        }

        await this._processRegistration(options);
    }

    /**
     * Process registration with WebAuthn.
     *
     * @private
     * @param {PublicKeyCredentialCreationOptionsJSON} options WebAuthn credential creation options.
     * @returns {Promise<void>}
     */
    async _processRegistration(options) {
        try {
            const processedOptions = this._processExtensionsInput(options);

            let credential = await startRegistration({
                optionsJSON: processedOptions,
                useAutoRegister: this.autoRegisterValue,
            });

            credential = this._processExtensionsOutput(credential);
            this._dispatchEvent('webauthn:registration:credential', { credential });

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
                'webauthn:registration'
            );

            if (verificationResult && this.hasSuccessRedirectUriValue) {
                window.location.replace(this.successRedirectUriValue);
            }
        } catch (error) {
            // Check if this is a WebAuthn-specific error
            if (error instanceof WebAuthnError) {
                this._dispatchEvent('webauthn:registration:error', {
                    error,
                    code: error.code,
                    name: error.name,
                });
            } else {
                this._dispatchEvent('webauthn:registration:error', { error });
            }
        }
    }
}
