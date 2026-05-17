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
    static values: {
        optionsUrl: {
            type: StringConstructor;
            default: string;
        };
        resultUrl: {
            type: StringConstructor;
            default: string;
        };
        submitViaForm: {
            type: BooleanConstructor;
            default: boolean;
        };
        successRedirectUri: StringConstructor;
        autoRegister: {
            type: BooleanConstructor;
            default: boolean;
        };
        requestHeaders: {
            type: ObjectConstructor;
            default: {
                'Content-Type': string;
                Accept: string;
            };
        };
    };
    connect(): Promise<void>;
    /**
     * Register a new WebAuthn credential.
     *
     * @param {Event} event Form submit event.
     * @returns {Promise<void>}
     */
    register(event: Event): Promise<void>;
    /**
     * Start registration process.
     *
     * @private
     * @returns {Promise<void>}
     */
    private _startRegistration;
    /**
     * Process registration with WebAuthn.
     *
     * @private
     * @param {PublicKeyCredentialCreationOptionsJSON} options WebAuthn credential creation options.
     * @returns {Promise<void>}
     */
    private _processRegistration;
}
export type PublicKeyCredentialCreationOptionsJSON = import("@simplewebauthn/browser").PublicKeyCredentialCreationOptionsJSON;
export type RegistrationResponseJSON = import("@simplewebauthn/browser").RegistrationResponseJSON;
import BaseController from './base-controller.js';
