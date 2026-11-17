'use strict';

import { Controller } from '@hotwired/stimulus';
import {
    browserSupportsWebAuthn,
    browserSupportsWebAuthnAutofill,
    startAuthentication,
    startRegistration,
    base64URLStringToBuffer,
    bufferToBase64URLString,
} from '@simplewebauthn/browser';

/**
 * @typedef {import('@simplewebauthn/browser').PublicKeyCredentialCreationOptionsJSON} PublicKeyCredentialCreationOptionsJSON
 * @typedef {import('@simplewebauthn/browser').PublicKeyCredentialRequestOptionsJSON} PublicKeyCredentialRequestOptionsJSON
 * @typedef {import('@simplewebauthn/browser').RegistrationResponseJSON} RegistrationResponseJSON
 * @typedef {import('@simplewebauthn/browser').AuthenticationResponseJSON} AuthenticationResponseJSON
 */

/**
 * Legacy combined WebAuthn Stimulus controller.
 *
 * Handles both registration (`signup`) and authentication (`signin`) on the same element.
 * New integrations should prefer the dedicated {@link AuthenticationController} and
 * {@link RegistrationController} controllers.
 *
 * @deprecated since 5.3.0, kept for backward compatibility. Will be removed in 6.0.
 */
export default class WebauthnController extends Controller {
    static values = {
        requestResultUrl: { type: String, default: '/request' },
        requestOptionsUrl: { type: String, default: '/request/options' },
        requestResultField: { type: String, default: null },
        requestSuccessRedirectUri: String,
        creationResultUrl: { type: String, default: '/creation' },
        creationOptionsUrl: { type: String, default: '/creation/options' },
        creationResultField: { type: String, default: null },
        creationSuccessRedirectUri: String,
        usernameField: { type: String, default: 'username' },
        displayNameField: { type: String, default: 'displayName' },
        attestationField: { type: String, default: 'attestation' },
        userVerificationField: { type: String, default: 'userVerification' },
        residentKeyField: { type: String, default: 'residentKey' },
        authenticatorAttachmentField: { type: String, default: 'authenticatorAttachment' },
        useBrowserAutofill: { type: Boolean, default: false },
        requestHeaders: {
            type: Object,
            default: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
                mode: 'no-cors',
                credentials: 'include',
            },
        },
    };

    connect = async () => {
        const options = {
            requestResultUrl: this.requestResultUrlValue,
            requestOptionsUrl: this.requestOptionsUrlValue,
            requestResultField: this.requestResultFieldValue ?? null,
            creationResultField: this.creationResultFieldValue ?? null,
            requestSuccessRedirectUri: this.requestSuccessRedirectUriValue ?? null,
            creationResultUrl: this.creationResultUrlValue,
            creationOptionsUrl: this.creationOptionsUrlValue,
            creationSuccessRedirectUri: this.creationSuccessRedirectUriValue ?? null,
        };

        this._dispatchEvent('webauthn:connect', { options });
        const supportAutofill = await browserSupportsWebAuthnAutofill();

        if (supportAutofill && this.useBrowserAutofillValue) {
            const optionsResponseJson = await this._getPublicKeyCredentialRequestOptions({});
            if (!optionsResponseJson) {
                return;
            }
            this._processSignin(optionsResponseJson, true);
        }
    };

    /**
     * Authenticate the user (assertion ceremony).
     *
     * @param {Event} event Form submit event.
     * @returns {Promise<void>}
     */
    async signin(event) {
        if (!browserSupportsWebAuthn()) {
            this._dispatchEvent('webauthn:unsupported', {});
            return;
        }
        event.preventDefault();
        const optionsResponseJson = await this._getPublicKeyCredentialRequestOptions(null);
        if (!optionsResponseJson) {
            return;
        }
        this._processSignin(optionsResponseJson, false);
    }

    /**
     * @private
     * @param {PublicKeyCredentialRequestOptionsJSON} optionsResponseJson
     * @param {boolean} useBrowserAutofill
     * @returns {Promise<void>}
     */
    async _processSignin(optionsResponseJson, useBrowserAutofill) {
        try {
            optionsResponseJson = this._processExtensionsInput(optionsResponseJson);
            let authenticatorResponse = await startAuthentication({
                optionsJSON: optionsResponseJson,
                useBrowserAutofill,
            });
            authenticatorResponse = this._processExtensionsOutput(authenticatorResponse);
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });
            if (this.requestResultFieldValue && this.element instanceof HTMLFormElement) {
                this.element
                    .querySelector(this.requestResultFieldValue)
                    ?.setAttribute('value', JSON.stringify(authenticatorResponse));
                this.element.submit();
                return;
            }

            const assertionResponse = await this._getAssertionResponse(authenticatorResponse);
            if (assertionResponse !== false && this.requestSuccessRedirectUriValue) {
                window.location.replace(this.requestSuccessRedirectUriValue);
            }
        } catch (e) {
            this._dispatchEvent('webauthn:assertion:failure', { exception: e, assertionResponse: null });
            return;
        }
    }

    /**
     * Register a new credential (attestation ceremony).
     *
     * @param {Event} event Form submit event.
     * @returns {Promise<void>}
     */
    async signup(event) {
        try {
            if (!browserSupportsWebAuthn()) {
                this._dispatchEvent('webauthn:unsupported', {});
                return;
            }
            event.preventDefault();
            let optionsResponseJson = await this._getPublicKeyCredentialCreationOptions(null);
            if (!optionsResponseJson) {
                return;
            }

            optionsResponseJson = this._processExtensionsInput(optionsResponseJson);
            let authenticatorResponse = await startRegistration({ optionsJSON: optionsResponseJson });
            authenticatorResponse = this._processExtensionsOutput(authenticatorResponse);
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });
            if (this.creationResultFieldValue && this.element instanceof HTMLFormElement) {
                this.element
                    .querySelector(this.creationResultFieldValue)
                    ?.setAttribute('value', JSON.stringify(authenticatorResponse));
                this.element.submit();
                return;
            }

            const attestationResponseJSON = await this._getAttestationResponse(authenticatorResponse);
            if (attestationResponseJSON !== false && this.creationSuccessRedirectUriValue) {
                window.location.replace(this.creationSuccessRedirectUriValue);
            }
        } catch (e) {
            this._dispatchEvent('webauthn:attestation:failure', { exception: e, assertionResponse: null });
            return;
        }
    }

    /**
     * @private
     * @param {string} name
     * @param {Record<string, unknown>} payload
     */
    _dispatchEvent(name, payload) {
        this.element.dispatchEvent(new CustomEvent(name, { detail: payload, bubbles: true }));
    }

    /**
     * @private
     * @returns {Record<string, unknown> | undefined}
     */
    _getData() {
        let data = new FormData();
        try {
            this.element.reportValidity();
            if (!this.element.checkValidity()) {
                return;
            }
            data = new FormData(this.element);
        } catch (_e) {
            //Nothing to do
        }

        function removeEmpty(obj) {
            return Object.entries(obj)
                .filter(([, v]) => v !== null && v !== '')
                .reduce((acc, [k, v]) => ({ ...acc, [k]: v === Object(v) ? removeEmpty(v) : v }), {});
        }

        return removeEmpty({
            username: data.get(this.usernameFieldValue),
            displayName: data.get(this.displayNameFieldValue),
            attestation: data.get(this.attestationFieldValue),
            userVerification: data.get(this.userVerificationFieldValue),
            residentKey: data.get(this.residentKeyFieldValue),
            authenticatorAttachment: data.get(this.authenticatorAttachmentFieldValue),
        });
    }

    /**
     * @private
     * @param {Record<string, unknown> | null} formData
     * @returns {Promise<PublicKeyCredentialRequestOptionsJSON | false>}
     */
    async _getPublicKeyCredentialRequestOptions(formData) {
        return this._getOptions(this.requestOptionsUrlValue, formData);
    }

    /**
     * @private
     * @param {Record<string, unknown> | null} formData
     * @returns {Promise<PublicKeyCredentialCreationOptionsJSON | false>}
     */
    async _getPublicKeyCredentialCreationOptions(formData) {
        return this._getOptions(this.creationOptionsUrlValue, formData);
    }

    /**
     * @private
     * @template T
     * @param {string} url
     * @param {Record<string, unknown> | null} formData
     * @returns {Promise<T | false>}
     */
    async _getOptions(url, formData) {
        const data = formData || this._getData();
        if (!data) {
            return false;
        }

        this._dispatchEvent('webauthn:options:request', { data });
        const optionsResponse = await fetch(url, {
            headers: { ...this.requestHeadersValue },
            method: 'POST',
            body: JSON.stringify(data),
        });
        if (!optionsResponse.ok) {
            this._dispatchEvent('webauthn:options:failure', { exception: null, optionsResponse });
            return false;
        }

        const options = await optionsResponse.json();
        this._dispatchEvent('webauthn:options:success', { data: options });

        return options;
    }

    /**
     * @private
     * @param {RegistrationResponseJSON} authenticatorResponse
     */
    async _getAttestationResponse(authenticatorResponse) {
        return this._getResult(this.creationResultUrlValue, 'webauthn:attestation:', authenticatorResponse);
    }

    /**
     * @private
     * @param {AuthenticationResponseJSON} authenticatorResponse
     */
    async _getAssertionResponse(authenticatorResponse) {
        return this._getResult(this.requestResultUrlValue, 'webauthn:assertion:', authenticatorResponse);
    }

    /**
     * @private
     * @param {string} url
     * @param {string} eventPrefix
     * @param {RegistrationResponseJSON | AuthenticationResponseJSON} authenticatorResponse
     */
    async _getResult(url, eventPrefix, authenticatorResponse) {
        const attestationResponse = await fetch(url, {
            headers: { ...this.requestHeadersValue },
            method: 'POST',
            body: JSON.stringify(authenticatorResponse),
        });
        if (!attestationResponse.ok) {
            this._dispatchEvent(eventPrefix + 'failure', {});
            return false;
        }
        const attestationResponseJSON = await attestationResponse.json();
        this._dispatchEvent(eventPrefix + 'success', { data: attestationResponseJSON });

        return attestationResponseJSON;
    }

    /**
     * @private
     * @template {PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON} T
     * @param {T} options
     * @returns {T}
     */
    _processExtensionsInput(options) {
        if (!options || !options.extensions) {
            return options;
        }

        if (options.extensions.prf) {
            options.extensions.prf = this._processPrfInput(options.extensions.prf);
        }

        return options;
    }

    /**
     * @private
     * @param {Record<string, any>} prf
     * @returns {Record<string, any>}
     */
    _processPrfInput(prf) {
        if (prf.eval) {
            prf.eval = this._importPrfValues(prf.eval);
        }

        if (prf.evalByCredential) {
            Object.keys(prf.evalByCredential).forEach((key) => {
                prf.evalByCredential[key] = this._importPrfValues(prf.evalByCredential[key]);
            });
        }

        return prf;
    }

    /**
     * @private
     * @param {{ first: string, second?: string }} values
     * @returns {{ first: ArrayBuffer, second?: ArrayBuffer }}
     */
    _importPrfValues(values) {
        const result = { ...values };
        result.first = base64URLStringToBuffer(values.first);
        if (values.second) {
            result.second = base64URLStringToBuffer(values.second);
        }

        return result;
    }

    /**
     * @private
     * @template {RegistrationResponseJSON | AuthenticationResponseJSON} T
     * @param {T} credential
     * @returns {T}
     */
    _processExtensionsOutput(credential) {
        if (!credential || !credential.clientExtensionResults) {
            return credential;
        }

        if (credential.clientExtensionResults.prf) {
            credential.clientExtensionResults.prf = this._processPrfOutput(credential.clientExtensionResults.prf);
        }

        return credential;
    }

    /**
     * @private
     * @param {Record<string, any>} prf
     * @returns {Record<string, any>}
     */
    _processPrfOutput(prf) {
        if (!prf.results) {
            return prf;
        }

        prf.results = this._exportPrfValues(prf.results);

        return prf;
    }

    /**
     * @private
     * @param {{ first: ArrayBuffer, second?: ArrayBuffer }} values
     * @returns {{ first: string, second?: string }}
     */
    _exportPrfValues(values) {
        const result = { ...values };
        result.first = bufferToBase64URLString(values.first);
        if (values.second) {
            result.second = bufferToBase64URLString(values.second);
        }

        return result;
    }
}
