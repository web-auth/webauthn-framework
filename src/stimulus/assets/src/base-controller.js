'use strict';

import { Controller } from '@hotwired/stimulus';
import { base64URLStringToBuffer, bufferToBase64URLString } from '@simplewebauthn/browser';

/**
 * @typedef {import('@simplewebauthn/browser').PublicKeyCredentialCreationOptionsJSON} PublicKeyCredentialCreationOptionsJSON
 * @typedef {import('@simplewebauthn/browser').PublicKeyCredentialRequestOptionsJSON} PublicKeyCredentialRequestOptionsJSON
 * @typedef {import('@simplewebauthn/browser').RegistrationResponseJSON} RegistrationResponseJSON
 * @typedef {import('@simplewebauthn/browser').AuthenticationResponseJSON} AuthenticationResponseJSON
 */

/**
 * @typedef {Object} FieldTargetMapping
 * @property {string} name Form data key to extract.
 * @property {string} targetName Stimulus target name (without the `Target` suffix).
 */

/**
 * @typedef {Object} PrfValuesJSON
 * @property {string} first Base64url-encoded first value.
 * @property {string} [second] Base64url-encoded second value (optional).
 */

/**
 * @typedef {Object} PrfValuesBuffer
 * @property {ArrayBuffer} first Decoded first value.
 * @property {ArrayBuffer} [second] Decoded second value (optional).
 */

/**
 * Base controller for WebAuthn operations.
 *
 * Contains shared logic for authentication and registration controllers.
 *
 * @abstract
 */
export default class BaseController extends Controller {
    static values = {
        requestHeaders: {
            type: Object,
            default: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
        },
    };

    /**
     * Fetch options from the server.
     *
     * @template {PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON} T
     * @param {string} url The URL to fetch options from.
     * @param {Record<string, unknown>} formData The form data to send as JSON body.
     * @param {string} eventPrefix Prefix for dispatched events.
     * @returns {Promise<T|false>} The options object or `false` on error.
     */
    async _fetchOptions(url, formData, eventPrefix) {
        this._dispatchEvent(`${eventPrefix}:options:request`, { data: formData });

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: this.requestHeadersValue,
                body: JSON.stringify(formData),
            });

            if (!response.ok) {
                this._dispatchEvent(`${eventPrefix}:options:error`, { response });
                return false;
            }

            const options = await response.json();
            this._dispatchEvent(`${eventPrefix}:options:success`, { options });

            return options;
        } catch (error) {
            this._dispatchEvent(`${eventPrefix}:options:error`, { error });
            return false;
        }
    }

    /**
     * Verify credential with the server.
     *
     * @template T
     * @param {string} url The URL to verify credential at.
     * @param {RegistrationResponseJSON | AuthenticationResponseJSON} credential The credential to verify.
     * @param {string} eventPrefix Prefix for dispatched events.
     * @returns {Promise<T|false>} The verification result or `false` on error.
     */
    async _verifyCredential(url, credential, eventPrefix) {
        this._dispatchEvent(`${eventPrefix}:verify:request`, { credential });

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: this.requestHeadersValue,
                body: JSON.stringify(credential),
            });

            if (!response.ok) {
                this._dispatchEvent(`${eventPrefix}:verify:error`, { response });
                return false;
            }

            const result = await response.json();
            this._dispatchEvent(`${eventPrefix}:verify:success`, { result });

            return result;
        } catch (error) {
            this._dispatchEvent(`${eventPrefix}:verify:error`, { error });
            return false;
        }
    }

    /**
     * Get form data and validate.
     *
     * @param {FieldTargetMapping[]} [fieldTargets] Field mappings.
     * @returns {Record<string, unknown> | null} Form data, or `null` if the form is invalid.
     */
    _getFormData(fieldTargets = []) {
        if (!(this.element instanceof HTMLFormElement)) {
            return {};
        }

        try {
            this.element.reportValidity();
            if (!this.element.checkValidity()) {
                return null;
            }

            const formData = new FormData(this.element);
            const data = {};

            // Extract data from targets or form fields
            fieldTargets.forEach(({ name, targetName }) => {
                const targetHasMethod = `has${targetName.charAt(0).toUpperCase() + targetName.slice(1)}Target`;
                const targetProperty = `${targetName}Target`;

                if (this[targetHasMethod]) {
                    data[name] = this[targetProperty].value;
                } else if (formData.has(name)) {
                    data[name] = formData.get(name);
                }
            });

            return this._removeEmpty(data);
        } catch (_error) {
            return {};
        }
    }

    /**
     * Remove empty values from an object recursively.
     *
     * @param {Record<string, unknown>} obj Object to clean.
     * @returns {Record<string, unknown>} Cleaned object.
     */
    _removeEmpty(obj) {
        return Object.entries(obj)
            .filter(([, v]) => v !== null && v !== '')
            .reduce((acc, [k, v]) => ({ ...acc, [k]: v === Object(v) ? this._removeEmpty(v) : v }), {});
    }

    /**
     * Process extensions input (e.g., PRF) before passing options to the authenticator.
     *
     * @template {PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON} T
     * @param {T} options WebAuthn options.
     * @returns {T} Processed options.
     */
    _processExtensionsInput(options) {
        if (!options?.extensions) {
            return options;
        }

        if (options.extensions.prf) {
            options.extensions.prf = this._processPrfInput(options.extensions.prf);
        }

        return options;
    }

    /**
     * Process PRF input by decoding base64url strings into ArrayBuffers.
     *
     * @param {Record<string, any>} prf PRF extension object.
     * @returns {Record<string, any>} Processed PRF object.
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
     * Import PRF values from base64url strings to ArrayBuffer.
     *
     * @param {PrfValuesJSON} values PRF values with base64url strings.
     * @returns {PrfValuesBuffer} PRF values with ArrayBuffers.
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
     * Process extensions output (e.g., PRF) after the authenticator answers.
     *
     * @template {RegistrationResponseJSON | AuthenticationResponseJSON} T
     * @param {T} credential WebAuthn credential.
     * @returns {T} Processed credential.
     */
    _processExtensionsOutput(credential) {
        if (!credential?.clientExtensionResults) {
            return credential;
        }

        if (credential.clientExtensionResults.prf) {
            credential.clientExtensionResults.prf = this._processPrfOutput(credential.clientExtensionResults.prf);
        }

        return credential;
    }

    /**
     * Process PRF output by encoding ArrayBuffers to base64url strings.
     *
     * @param {Record<string, any>} prf PRF extension result.
     * @returns {Record<string, any>} Processed PRF result.
     */
    _processPrfOutput(prf) {
        if (!prf.results) {
            return prf;
        }

        prf.results = this._exportPrfValues(prf.results);
        return prf;
    }

    /**
     * Export PRF values from ArrayBuffer to base64url strings.
     *
     * @param {PrfValuesBuffer} values PRF values with ArrayBuffers.
     * @returns {PrfValuesJSON} PRF values with base64url strings.
     */
    _exportPrfValues(values) {
        const result = { ...values };
        result.first = bufferToBase64URLString(values.first);
        if (values.second) {
            result.second = bufferToBase64URLString(values.second);
        }
        return result;
    }

    /**
     * Dispatch a bubbling custom event from the controller element.
     *
     * @param {string} name Event name.
     * @param {Record<string, unknown>} payload Event detail payload.
     */
    _dispatchEvent(name, payload) {
        this.element.dispatchEvent(new CustomEvent(name, { detail: payload, bubbles: true }));
    }
}
