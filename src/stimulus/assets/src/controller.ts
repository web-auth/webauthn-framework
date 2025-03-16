'use strict';

import { Controller } from '@hotwired/stimulus';
import {
    AuthenticationResponseJSON,
    RegistrationResponseJSON,
    PublicKeyCredentialRequestOptionsJSON,
    PublicKeyCredentialCreationOptionsJSON
} from '@simplewebauthn/types';
import { browserSupportsWebAuthn, browserSupportsWebAuthnAutofill, startAuthentication, startRegistration, base64URLStringToBuffer, bufferToBase64URLString } from '@simplewebauthn/browser';

export default class extends Controller {
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
        requestHeaders: { type: Object, default: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'mode': 'no-cors',
                'credentials': 'include'
        } },
    };

    declare readonly requestResultUrlValue: string;
    declare readonly requestOptionsUrlValue: string;
    declare readonly requestResultFieldValue?: string;
    declare readonly requestSuccessRedirectUriValue?: string;
    declare readonly creationResultUrlValue: string;
    declare readonly creationOptionsUrlValue: string;
    declare readonly creationResultFieldValue?: string;
    declare readonly creationSuccessRedirectUriValue?: string;
    declare readonly usernameFieldValue: string;
    declare readonly displayNameFieldValue: string;
    declare readonly attestationFieldValue: string;
    declare readonly userVerificationFieldValue: string;
    declare readonly residentKeyFieldValue: string;
    declare readonly authenticatorAttachmentFieldValue: string;
    declare readonly useBrowserAutofillValue: boolean;
    declare readonly requestHeadersValue: object;

    public connect = async () => {
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
    }

    public async signin(event: Event): Promise<void> {
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

    private async _processSignin(optionsResponseJson: Object, useBrowserAutofill: boolean): Promise<void> {
        try {
            // @ts-ignore
            optionsResponseJson = this._processExtensionsInput(optionsResponseJson);
            // @ts-ignore
            let authenticatorResponse = await startAuthentication({ optionsJSON: optionsResponseJson, useBrowserAutofill });
            // @ts-ignore
            authenticatorResponse = this._processExtensionsOutput(authenticatorResponse);
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });
            if (this.requestResultFieldValue && this.element instanceof HTMLFormElement) {
                this.element.querySelector(this.requestResultFieldValue)?.setAttribute('value', JSON.stringify(authenticatorResponse));
                this.element.submit();
                return;
            }

            const assertionResponse = await this._getAssertionResponse(authenticatorResponse);
            if (assertionResponse !== false && this.requestSuccessRedirectUriValue) {
                window.location.replace(this.requestSuccessRedirectUriValue);
            }
        } catch (e) {
            this._dispatchEvent('webauthn:assertion:failure', {exception: e, assertionResponse: null});
            return;
        }
    }

    public async signup(event: Event): Promise<void> {
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
            // @ts-ignore
            let authenticatorResponse = await startRegistration({ optionsJSON: optionsResponseJson });
            // @ts-ignore
            authenticatorResponse = this._processExtensionsOutput(authenticatorResponse);
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });
            if (this.creationResultFieldValue && this.element instanceof HTMLFormElement) {
                this.element.querySelector(this.creationResultFieldValue)?.setAttribute('value', JSON.stringify(authenticatorResponse));
                this.element.submit();
                return;
            }

            const attestationResponseJSON = await this._getAttestationResponse(authenticatorResponse);
            if (attestationResponseJSON !== false && this.creationSuccessRedirectUriValue) {
                window.location.replace(this.creationSuccessRedirectUriValue);
            }
        } catch (e) {
            this._dispatchEvent('webauthn:attestation:failure', {exception: e, assertionResponse: null});
            return;
        }
    }

    private _dispatchEvent(name: string, payload: any): void {
        this.element.dispatchEvent(new CustomEvent(name, { detail: payload, bubbles: true }));
    }

    private  _getData() {
        let data = new FormData();
        try {
            // @ts-ignore
            this.element.reportValidity()
            // @ts-ignore
            if (!this.element.checkValidity()) {
                return;
            }
            // @ts-ignore
            data = new FormData(this.element);
        } catch (e) {
            //Nothing to do
        }

        function removeEmpty(obj: object): any {
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

    private async _getPublicKeyCredentialRequestOptions(formData: null|Object): Promise<false|Object> {
        return this._getOptions(this.requestOptionsUrlValue, formData);
    }

    private async _getPublicKeyCredentialCreationOptions(formData: null|Object): Promise<false|Object> {
        return this._getOptions(this.creationOptionsUrlValue, formData);
    }

    private async _getOptions(url: string, formData: null|Object): Promise<false|Object> {
        const data = formData || this._getData();
        if (!data) {
            return false;
        }

        this._dispatchEvent('webauthn:options:request', { data });
        const optionsResponse = await fetch(url, {
            headers: {...this.requestHeadersValue},
            method: 'POST',
            body: JSON.stringify(data)
        });
        if (!optionsResponse.ok) {
            this._dispatchEvent('webauthn:options:failure', {exception: null, optionsResponse});
            return false;
        }

        const options = await optionsResponse.json();
        this._dispatchEvent('webauthn:options:success', {data: options});

        return options;
    }

    private async _getAttestationResponse(authenticatorResponse: RegistrationResponseJSON) {
        return this._getResult(this.creationResultUrlValue, 'webauthn:attestation:', authenticatorResponse);
    }

    private async _getAssertionResponse(authenticatorResponse: AuthenticationResponseJSON) {
        return this._getResult(this.requestResultUrlValue, 'webauthn:assertion:', authenticatorResponse);
    }

    private async _getResult(url: string, eventPrefix: string, authenticatorResponse: RegistrationResponseJSON|AuthenticationResponseJSON): Promise<false|Object> {

        const attestationResponse = await fetch(url, {
            headers: {...this.requestHeadersValue},
            method:'POST',
            body: JSON.stringify(authenticatorResponse)
        });
        if (!attestationResponse.ok) {
            this._dispatchEvent(eventPrefix+'failure', {});
            return false;
        }
        const attestationResponseJSON = await attestationResponse.json();
        this._dispatchEvent(eventPrefix+'success', {data:attestationResponseJSON});

        return attestationResponseJSON;
    }

    private _processExtensionsInput(options: Object|PublicKeyCredentialRequestOptionsJSON|PublicKeyCredentialCreationOptionsJSON): Object|PublicKeyCredentialRequestOptionsJSON|PublicKeyCredentialCreationOptionsJSON {
        // @ts-ignore
        if (!options || !options.extensions) {
            return options;
        }

        // @ts-ignore
        if (options.extensions.prf) {
            // @ts-ignore
            options.extensions.prf = this._processPrfInput(options.extensions.prf);
        }

        return options;
    }

    private _processPrfInput(prf: Object): Object {
        // @ts-ignore
        if (prf.eval) {
            // @ts-ignore
            prf.eval = this._importPrfValues(eval);
        }

        // @ts-ignore
        if (prf.evalByCredential) {
            // @ts-ignore
            Object.keys(prf.evalByCredential).forEach((key) => {
                // @ts-ignore
                prf.evalByCredential[key] = this._importPrfValues(prf.evalByCredential[key]);
            });
        }

        return prf;
    }

    private _importPrfValues(values: Object): Object {
        // @ts-ignore
        values.first = base64URLStringToBuffer(values.first);
        // @ts-ignore
        if (values.second) {
            // @ts-ignore
            values.second = base64URLStringToBuffer(values.second);
        }

        return values;
    }

    private _processExtensionsOutput(options: Object|AuthenticationResponseJSON|RegistrationResponseJSON): Object|PublicKeyCredentialRequestOptionsJSON|PublicKeyCredentialCreationOptionsJSON {
        // @ts-ignore
        if (!options || !options.extensions) {
            return options;
        }

        // @ts-ignore
        if (options.extensions.prf) {
            // @ts-ignore
            options.extensions.prf = this._processPrfOutput(options.extensions.prf);
        }

        return options;
    }

    private _processPrfOutput(prf: Object): Object {
        // @ts-ignore
        if (!prf.result) {
            return prf
        }

        // @ts-ignore
        prf.result = this._exportPrfValues(prf.result);

        return prf;
    }

    private _exportPrfValues(values: Object): Object {
        // @ts-ignore
        values.first = bufferToBase64URLString(values.first);
        // @ts-ignore
        if (values.second) {
            // @ts-ignore
            values.second = bufferToBase64URLString(values.second);
        }

        return values;
    }
}
