'use strict';

import { Controller } from '@hotwired/stimulus';
import {
    base64URLStringToBuffer,
    browserSupportsWebAuthnAutofill,
    bufferToBase64URLString,
    WebAuthnAbortService,
} from '@simplewebauthn/browser';

import { dispatchSignals } from './signals.js';

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

            await dispatchSignals(result);

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

        // CTAP 2.1 §12.2: credBlob ships as base64url over JSON, but the
        // browser expects a BufferSource. The string form is what
        // CredentialBlobInputExtension produces server-side.
        if (typeof options.extensions.credBlob === 'string') {
            options.extensions.credBlob = base64URLStringToBuffer(options.extensions.credBlob);
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
     * Idempotent: values that are already ArrayBuffers are passed through.
     *
     * @param {PrfValuesJSON} values PRF values with base64url strings.
     * @returns {PrfValuesBuffer} PRF values with ArrayBuffers.
     */
    _importPrfValues(values) {
        const result = { ...values };
        if (typeof values.first === 'string') {
            result.first = base64URLStringToBuffer(values.first);
        }
        if (typeof values.second === 'string') {
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

        // CTAP 2.1 §12.2: getCredBlob assertion output is an ArrayBuffer of
        // raw bytes — encode to base64url so the JSON we POST back to the
        // server is round-trippable through CredentialBlobAssertionOutput.
        if (credential.clientExtensionResults.credBlob instanceof ArrayBuffer) {
            credential.clientExtensionResults.credBlob = bufferToBase64URLString(
                credential.clientExtensionResults.credBlob
            );
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
     * Idempotent: values that are already strings (typically because the
     * native L3 `toJSON()` already encoded them) are passed through unchanged.
     *
     * @param {PrfValuesBuffer} values PRF values with ArrayBuffers.
     * @returns {PrfValuesJSON} PRF values with base64url strings.
     */
    _exportPrfValues(values) {
        const result = { ...values };
        if (values.first instanceof ArrayBuffer) {
            result.first = bufferToBase64URLString(values.first);
        }
        if (values.second instanceof ArrayBuffer) {
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

    /**
     * Navigate to the given URI on a successful ceremony when
     * `successRedirectUri` is configured. Extracted from the consumers so
     * tests can spy on this method without having to redefine `window.location`
     * (which jsdom marks as non-configurable).
     *
     * @param {string} uri
     */
    _redirect(uri) {
        window.location.replace(uri);
    }

    /**
     * Read the WebAuthn L3 §5.1.7 client capability map for the current
     * user agent. Memoised per controller instance.
     *
     * On user agents that do not implement
     * `PublicKeyCredential.getClientCapabilities()` (everything pre-L3) this
     * returns a synthetic plain object built from the legacy feature
     * detectors we still depend on:
     *
     *  - `conditionalGet` ← `browserSupportsWebAuthnAutofill()` (which
     *    itself wraps the deprecated `isConditionalMediationAvailable()`).
     *
     * Other capabilities are reported as `false` on the fallback path —
     * callers that depend on them should treat absence as "unsupported"
     * rather than "unknown" and either skip the optional behaviour or
     * surface it to the user.
     *
     * @returns {Promise<Object<string, boolean>>}
     */
    async _getClientCapabilities() {
        if (this._clientCapabilitiesCache !== undefined) {
            return this._clientCapabilitiesCache;
        }

        if (
            typeof PublicKeyCredential !== 'undefined' &&
            typeof PublicKeyCredential.getClientCapabilities === 'function'
        ) {
            const native = await PublicKeyCredential.getClientCapabilities();
            // The spec returns a MapLike. Normalise to a plain object so
            // callers can treat it like any other JSON payload.
            this._clientCapabilitiesCache =
                native instanceof Map ? Object.fromEntries(native.entries()) : { ...native };
            return this._clientCapabilitiesCache;
        }

        const supportsAutofill = await browserSupportsWebAuthnAutofill();
        this._clientCapabilitiesCache = {
            conditionalGet: supportsAutofill,
        };
        return this._clientCapabilitiesCache;
    }

    /**
     * Whether the user agent ships the WebAuthn L3 §5.1.13–14 JSON helpers
     * (`PublicKeyCredential.parseCreationOptionsFromJSON`,
     * `parseRequestOptionsFromJSON`, `credential.toJSON()`). When true the
     * controllers call `navigator.credentials.{create,get}()` directly —
     * the native parser converts every standard field, including known
     * extensions, so the manual `_processExtensionsInput`/`Output` passes
     * are unnecessary on this code path.
     *
     * Caveat: a controller method that depends on `toJSON()` should also
     * check that the returned credential exposes it, since some user agents
     * may ship the parser without the serializer or vice-versa.
     *
     * @returns {boolean}
     */
    _supportsNativeJsonHelpers() {
        return (
            typeof PublicKeyCredential !== 'undefined' &&
            typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function' &&
            typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function'
        );
    }

    /**
     * Run a registration ceremony via the native WebAuthn L3 helpers.
     * Caller must have checked {@see _supportsNativeJsonHelpers} first.
     *
     * @param {Object} optionsJSON - WebAuthn credential creation options (canonical JSON shape)
     * @param {Object} extras - Extra options forwarded to navigator.credentials.create()
     * @returns {Promise<Object>} JSON-serialised credential (via credential.toJSON())
     */
    async _nativeCreate(optionsJSON, extras = {}) {
        const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(optionsJSON);
        const credential = await navigator.credentials.create({
            publicKey,
            signal: WebAuthnAbortService.createNewAbortSignal(),
            ...extras,
        });
        if (credential === null) {
            throw new Error('navigator.credentials.create() returned null');
        }
        return credential.toJSON();
    }

    /**
     * Run an assertion ceremony via the native WebAuthn L3 helpers.
     * Caller must have checked {@see _supportsNativeJsonHelpers} first.
     *
     * @param {Object} optionsJSON - WebAuthn credential request options (canonical JSON shape)
     * @param {Object} extras - Extra options forwarded to navigator.credentials.get()
     * @returns {Promise<Object>} JSON-serialised credential (via credential.toJSON())
     */
    async _nativeGet(optionsJSON, extras = {}) {
        const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(optionsJSON);
        const credential = await navigator.credentials.get({
            publicKey,
            signal: WebAuthnAbortService.createNewAbortSignal(),
            ...extras,
        });
        if (credential === null) {
            throw new Error('navigator.credentials.get() returned null');
        }
        return credential.toJSON();
    }
}
