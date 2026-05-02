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
 * @property {boolean} submitViaFormValue - Whether to submit credential via form instead of API
 * @property {boolean} hasSubmitViaFormValue - Whether submitViaForm value is set
 * @property {string} successRedirectUriValue - URI to redirect to on success
 * @property {boolean} hasSuccessRedirectUriValue - Whether successRedirectUri value is set
 * @property {boolean} autoRegisterValue - Whether to use auto-register (conditional create)
 * @property {boolean} hasAutoRegisterValue - Whether autoRegister value is set
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
        submitViaForm: { type: Boolean, default: false },
        successRedirectUri: String,
        autoRegister: { type: Boolean, default: false },
    };

    async connect() {
        this._dispatchEvent('webauthn:registration:connect', {
            optionsUrl: this.optionsUrlValue,
            resultUrl: this.resultUrlValue,
            supportsPlatformAuthenticator: await platformAuthenticatorIsAvailable(),
            capabilities: await this._getClientCapabilities(),
        });
    }

    disconnect() {
        // Cancel any pending WebAuthn operations when the controller is disconnected
        // (e.g., when navigating away from the page)
        WebAuthnAbortService.cancelCeremony();
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
            let credential;
            if (this._supportsNativeJsonHelpers()) {
                // WebAuthn L3 §5.1.13: the user agent's native parser converts
                // every standard field, so we don't need _processExtensionsInput.
                // useAutoRegister maps to mediation: "conditional" per the
                // SimpleWebAuthn implementation note.
                credential = await this._nativeCreate(
                    options,
                    this.autoRegisterValue ? { mediation: 'conditional' } : {}
                );
            } else {
                const processedOptions = this._processExtensionsInput(options);
                credential = await startRegistration({
                    optionsJSON: processedOptions,
                    useAutoRegister: this.autoRegisterValue,
                });
            }

            // Run on both paths: subclasses (e.g. payment-controller) hook
            // here for non-WebAuthn-L3 extensions like SPC's `payment` that
            // PublicKeyCredential.toJSON() may not encode. The base helpers
            // are idempotent so values already encoded by toJSON() pass through.
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
