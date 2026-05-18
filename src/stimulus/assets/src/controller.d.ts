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
export default class WebauthnController extends Controller<Element> {
    static values: {
        requestResultUrl: {
            type: StringConstructor;
            default: string;
        };
        requestOptionsUrl: {
            type: StringConstructor;
            default: string;
        };
        requestResultField: {
            type: StringConstructor;
            default: any;
        };
        requestSuccessRedirectUri: StringConstructor;
        creationResultUrl: {
            type: StringConstructor;
            default: string;
        };
        creationOptionsUrl: {
            type: StringConstructor;
            default: string;
        };
        creationResultField: {
            type: StringConstructor;
            default: any;
        };
        creationSuccessRedirectUri: StringConstructor;
        usernameField: {
            type: StringConstructor;
            default: string;
        };
        displayNameField: {
            type: StringConstructor;
            default: string;
        };
        attestationField: {
            type: StringConstructor;
            default: string;
        };
        userVerificationField: {
            type: StringConstructor;
            default: string;
        };
        residentKeyField: {
            type: StringConstructor;
            default: string;
        };
        authenticatorAttachmentField: {
            type: StringConstructor;
            default: string;
        };
        useBrowserAutofill: {
            type: BooleanConstructor;
            default: boolean;
        };
        requestHeaders: {
            type: ObjectConstructor;
            default: {
                'Content-Type': string;
                Accept: string;
                mode: string;
                credentials: string;
            };
        };
    };
    constructor(context: import("@hotwired/stimulus").Context);
    connect: () => Promise<void>;
    /**
     * Authenticate the user (assertion ceremony).
     *
     * @param {Event} event Form submit event.
     * @returns {Promise<void>}
     */
    signin(event: Event): Promise<void>;
    /**
     * @private
     * @param {PublicKeyCredentialRequestOptionsJSON} optionsResponseJson
     * @param {boolean} useBrowserAutofill
     * @returns {Promise<void>}
     */
    private _processSignin;
    /**
     * Register a new credential (attestation ceremony).
     *
     * @param {Event} event Form submit event.
     * @returns {Promise<void>}
     */
    signup(event: Event): Promise<void>;
    /**
     * @private
     * @param {string} name
     * @param {Record<string, unknown>} payload
     */
    private _dispatchEvent;
    /**
     * @private
     * @returns {Record<string, unknown> | undefined}
     */
    private _getData;
    /**
     * @private
     * @param {Record<string, unknown> | null} formData
     * @returns {Promise<PublicKeyCredentialRequestOptionsJSON | false>}
     */
    private _getPublicKeyCredentialRequestOptions;
    /**
     * @private
     * @param {Record<string, unknown> | null} formData
     * @returns {Promise<PublicKeyCredentialCreationOptionsJSON | false>}
     */
    private _getPublicKeyCredentialCreationOptions;
    /**
     * @private
     * @template T
     * @param {string} url
     * @param {Record<string, unknown> | null} formData
     * @returns {Promise<T | false>}
     */
    private _getOptions;
    /**
     * @private
     * @param {RegistrationResponseJSON} authenticatorResponse
     */
    private _getAttestationResponse;
    /**
     * @private
     * @param {AuthenticationResponseJSON} authenticatorResponse
     */
    private _getAssertionResponse;
    /**
     * @private
     * @param {string} url
     * @param {string} eventPrefix
     * @param {RegistrationResponseJSON | AuthenticationResponseJSON} authenticatorResponse
     */
    private _getResult;
    /**
     * @private
     * @template {PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON} T
     * @param {T} options
     * @returns {T}
     */
    private _processExtensionsInput;
    /**
     * @private
     * @param {Record<string, any>} prf
     * @returns {Record<string, any>}
     */
    private _processPrfInput;
    /**
     * @private
     * @param {{ first: string, second?: string }} values
     * @returns {{ first: ArrayBuffer, second?: ArrayBuffer }}
     */
    private _importPrfValues;
    /**
     * @private
     * @template {RegistrationResponseJSON | AuthenticationResponseJSON} T
     * @param {T} options
     * @returns {T}
     */
    private _processExtensionsOutput;
    /**
     * @private
     * @param {Record<string, any>} prf
     * @returns {Record<string, any>}
     */
    private _processPrfOutput;
    /**
     * @private
     * @param {{ first: ArrayBuffer, second?: ArrayBuffer }} values
     * @returns {{ first: string, second?: string }}
     */
    private _exportPrfValues;
}
export type PublicKeyCredentialCreationOptionsJSON = import("@simplewebauthn/browser").PublicKeyCredentialCreationOptionsJSON;
export type PublicKeyCredentialRequestOptionsJSON = import("@simplewebauthn/browser").PublicKeyCredentialRequestOptionsJSON;
export type RegistrationResponseJSON = import("@simplewebauthn/browser").RegistrationResponseJSON;
export type AuthenticationResponseJSON = import("@simplewebauthn/browser").AuthenticationResponseJSON;
import { Controller } from '@hotwired/stimulus';
