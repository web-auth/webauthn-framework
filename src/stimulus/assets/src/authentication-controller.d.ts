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
        conditionalUi: {
            type: BooleanConstructor;
            default: boolean;
        };
        verifyAutofillInput: {
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
     * Authenticate the user via WebAuthn.
     *
     * @param {Event} event Form submit event.
     * @returns {Promise<void>}
     */
    authenticate(event: Event): Promise<void>;
    /**
     * Start authentication with conditional UI (browser autofill).
     *
     * @private
     * @returns {Promise<void>}
     */
    private _startAuthenticationWithConditionalUi;
    /**
     * Start authentication process.
     *
     * @private
     * @param {Partial<StartAuthenticationOpts>} [options] Additional options for startAuthentication.
     * @returns {Promise<void>}
     */
    private _startAuthentication;
    /**
     * Process authentication with WebAuthn.
     *
     * @private
     * @param {PublicKeyCredentialRequestOptionsJSON} credentialRequestOptions WebAuthn credential request options.
     * @param {Partial<StartAuthenticationOpts>} [startAuthenticationOptions] Options for startAuthentication call.
     * @returns {Promise<void>}
     */
    private _processAuthentication;
}
export type PublicKeyCredentialRequestOptionsJSON = import("@simplewebauthn/browser").PublicKeyCredentialRequestOptionsJSON;
export type AuthenticationResponseJSON = import("@simplewebauthn/browser").AuthenticationResponseJSON;
export type StartAuthenticationOpts = import("@simplewebauthn/browser").StartAuthenticationOpts;
import BaseController from './base-controller.js';
