'use strict';

import { browserSupportsWebAuthn, startRegistration } from '@simplewebauthn/browser';
import BaseController from './base-controller.js';

/**
 * Stimulus controller for WebAuthn registration (credential creation)
 *
 * Usage:
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
 *
 * @property {HTMLInputElement} usernameTarget - Username input element
 * @property {boolean} hasUsernameTarget - Whether username target exists
 * @property {HTMLSelectElement} attestationTarget - Attestation select element
 * @property {boolean} hasAttestationTarget - Whether attestation target exists
 * @property {HTMLSelectElement} residentKeyTarget - Resident key select element
 * @property {boolean} hasResidentKeyTarget - Whether residentKey target exists
 * @property {HTMLSelectElement} userVerificationTarget - User verification select element
 * @property {boolean} hasUserVerificationTarget - Whether userVerification target exists
 * @property {HTMLSelectElement} authenticatorAttachmentTarget - Authenticator attachment select element
 * @property {boolean} hasAuthenticatorAttachmentTarget - Whether authenticatorAttachment target exists
 * @property {HTMLInputElement} resultTarget - Result hidden input element
 * @property {boolean} hasResultTarget - Whether result target exists
 *
 * @property {string} optionsUrlValue - URL to fetch registration options from
 * @property {boolean} hasOptionsUrlValue - Whether optionsUrl value is set
 * @property {string} resultUrlValue - URL to verify registration result at
 * @property {boolean} hasResultUrlValue - Whether resultUrl value is set
 * @property {boolean} useResultTargetValue - Whether to use result target for form submission
 * @property {boolean} hasUseResultTargetValue - Whether useResultTarget value is set
 * @property {string} successRedirectUriValue - URI to redirect to on success
 * @property {boolean} hasSuccessRedirectUriValue - Whether successRedirectUri value is set
 */
export default class extends BaseController {
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
        useResultTarget: { type: Boolean, default: false },
        successRedirectUri: String,
    };

    connect() {
        this._dispatchEvent('webauthn:registration:connect', {
            optionsUrl: this.optionsUrlValue,
            resultUrl: this.resultUrlValue,
        });
    }

    /**
     * Register a new WebAuthn credential
     * @param {Event} event - Form submit event
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
     * Start registration process
     * @private
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
     * Process registration with WebAuthn
     * @private
     * @param {Object} options - WebAuthn credential creation options
     */
    async _processRegistration(options) {
        try {
            const processedOptions = this._processExtensionsInput(options);

            let credential = await startRegistration({
                optionsJSON: processedOptions,
            });

            credential = this._processExtensionsOutput(credential);
            this._dispatchEvent('webauthn:registration:credential', { credential });

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
                'webauthn:registration'
            );

            if (verificationResult && this.hasSuccessRedirectUriValue) {
                window.location.replace(this.successRedirectUriValue);
            }
        } catch (error) {
            this._dispatchEvent('webauthn:registration:error', { error });
        }
    }
}
