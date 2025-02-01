'use strict';

import { Controller } from '@hotwired/stimulus';
import {
    AuthenticationResponseJSON,
    RegistrationResponseJSON
} from '@simplewebauthn/types';
import { browserSupportsWebAuthn, browserSupportsWebAuthnAutofill, startAuthentication, startRegistration } from '@simplewebauthn/browser';

export default class extends Controller {
    static values = {
        requestResultUrl: { type: String, default: '/request' },
        requestOptionsUrl: { type: String, default: '/request/options' },
        requestSuccessRedirectUri: String,
        creationResultUrl: { type: String, default: '/creation' },
        creationOptionsUrl: { type: String, default: '/creation/options' },
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
    declare readonly requestSuccessRedirectUriValue?: string;
    declare readonly creationResultUrlValue: string;
    declare readonly creationOptionsUrlValue: string;
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
            const authenticatorResponse = await startAuthentication({ optionsJSON: optionsResponseJson, useBrowserAutofill });
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });

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
            const optionsResponseJson = await this._getPublicKeyCredentialCreationOptions(null);
            if (!optionsResponseJson) {
                return;
            }

            // @ts-ignore
            const authenticatorResponse = await startRegistration({ optionsJSON: optionsResponseJson });
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });

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
}
