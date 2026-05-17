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
export default class BaseController extends Controller<Element> {
    static values: {
        requestHeaders: {
            type: ObjectConstructor;
            default: {
                'Content-Type': string;
                Accept: string;
            };
        };
    };
    constructor(context: import("@hotwired/stimulus").Context);
    /**
     * Fetch options from the server.
     *
     * @template {PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON} T
     * @param {string} url The URL to fetch options from.
     * @param {Record<string, unknown>} formData The form data to send as JSON body.
     * @param {string} eventPrefix Prefix for dispatched events.
     * @returns {Promise<T|false>} The options object or `false` on error.
     */
    _fetchOptions<T extends PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON>(url: string, formData: Record<string, unknown>, eventPrefix: string): Promise<T | false>;
    /**
     * Verify credential with the server.
     *
     * @template T
     * @param {string} url The URL to verify credential at.
     * @param {RegistrationResponseJSON | AuthenticationResponseJSON} credential The credential to verify.
     * @param {string} eventPrefix Prefix for dispatched events.
     * @returns {Promise<T|false>} The verification result or `false` on error.
     */
    _verifyCredential<T>(url: string, credential: RegistrationResponseJSON | AuthenticationResponseJSON, eventPrefix: string): Promise<T | false>;
    /**
     * Get form data and validate.
     *
     * @param {FieldTargetMapping[]} [fieldTargets] Field mappings.
     * @returns {Record<string, unknown> | null} Form data, or `null` if the form is invalid.
     */
    _getFormData(fieldTargets?: FieldTargetMapping[]): Record<string, unknown> | null;
    /**
     * Remove empty values from an object recursively.
     *
     * @param {Record<string, unknown>} obj Object to clean.
     * @returns {Record<string, unknown>} Cleaned object.
     */
    _removeEmpty(obj: Record<string, unknown>): Record<string, unknown>;
    /**
     * Process extensions input (e.g., PRF) before passing options to the authenticator.
     *
     * @template {PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON} T
     * @param {T} options WebAuthn options.
     * @returns {T} Processed options.
     */
    _processExtensionsInput<T extends PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON>(options: T): T;
    /**
     * Process PRF input by decoding base64url strings into ArrayBuffers.
     *
     * @param {Record<string, any>} prf PRF extension object.
     * @returns {Record<string, any>} Processed PRF object.
     */
    _processPrfInput(prf: Record<string, any>): Record<string, any>;
    /**
     * Import PRF values from base64url strings to ArrayBuffer.
     *
     * @param {PrfValuesJSON} values PRF values with base64url strings.
     * @returns {PrfValuesBuffer} PRF values with ArrayBuffers.
     */
    _importPrfValues(values: PrfValuesJSON): PrfValuesBuffer;
    /**
     * Process extensions output (e.g., PRF) after the authenticator answers.
     *
     * @template {RegistrationResponseJSON | AuthenticationResponseJSON} T
     * @param {T} credential WebAuthn credential.
     * @returns {T} Processed credential.
     */
    _processExtensionsOutput<T extends RegistrationResponseJSON | AuthenticationResponseJSON>(credential: T): T;
    /**
     * Process PRF output by encoding ArrayBuffers to base64url strings.
     *
     * @param {Record<string, any>} prf PRF extension result.
     * @returns {Record<string, any>} Processed PRF result.
     */
    _processPrfOutput(prf: Record<string, any>): Record<string, any>;
    /**
     * Export PRF values from ArrayBuffer to base64url strings.
     *
     * @param {PrfValuesBuffer} values PRF values with ArrayBuffers.
     * @returns {PrfValuesJSON} PRF values with base64url strings.
     */
    _exportPrfValues(values: PrfValuesBuffer): PrfValuesJSON;
    /**
     * Dispatch a bubbling custom event from the controller element.
     *
     * @param {string} name Event name.
     * @param {Record<string, unknown>} payload Event detail payload.
     */
    _dispatchEvent(name: string, payload: Record<string, unknown>): void;
}
export type PublicKeyCredentialCreationOptionsJSON = import("@simplewebauthn/browser").PublicKeyCredentialCreationOptionsJSON;
export type PublicKeyCredentialRequestOptionsJSON = import("@simplewebauthn/browser").PublicKeyCredentialRequestOptionsJSON;
export type RegistrationResponseJSON = import("@simplewebauthn/browser").RegistrationResponseJSON;
export type AuthenticationResponseJSON = import("@simplewebauthn/browser").AuthenticationResponseJSON;
export type FieldTargetMapping = {
    /**
     * Form data key to extract.
     */
    name: string;
    /**
     * Stimulus target name (without the `Target` suffix).
     */
    targetName: string;
};
export type PrfValuesJSON = {
    /**
     * Base64url-encoded first value.
     */
    first: string;
    /**
     * Base64url-encoded second value (optional).
     */
    second?: string;
};
export type PrfValuesBuffer = {
    /**
     * Decoded first value.
     */
    first: ArrayBuffer;
    /**
     * Decoded second value (optional).
     */
    second?: ArrayBuffer;
};
import { Controller } from '@hotwired/stimulus';
