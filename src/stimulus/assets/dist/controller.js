import { Controller } from '@hotwired/stimulus';
import { browserSupportsWebAuthnAutofill, browserSupportsWebAuthn, startAuthentication, startRegistration } from '@simplewebauthn/browser';

class default_1 extends Controller {
    constructor() {
        super(...arguments);
        this.connect = async () => {
            var _a, _b;
            const options = {
                requestResultUrl: this.requestResultUrlValue,
                requestOptionsUrl: this.requestOptionsUrlValue,
                requestSuccessRedirectUri: (_a = this.requestSuccessRedirectUriValue) !== null && _a !== undefined ? _a : null,
                creationResultUrl: this.creationResultUrlValue,
                creationOptionsUrl: this.creationOptionsUrlValue,
                creationSuccessRedirectUri: (_b = this.creationSuccessRedirectUriValue) !== null && _b !== undefined ? _b : null,
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
    }
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
    async _processSignin(optionsResponseJson, useBrowserAutofill) {
        try {
            const authenticatorResponse = await startAuthentication({ optionsJSON: optionsResponseJson, useBrowserAutofill });
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });
            const assertionResponse = await this._getAssertionResponse(authenticatorResponse);
            if (assertionResponse !== false && this.requestSuccessRedirectUriValue) {
                window.location.replace(this.requestSuccessRedirectUriValue);
            }
        }
        catch (e) {
            this._dispatchEvent('webauthn:assertion:failure', { exception: e, assertionResponse: null });
            return;
        }
    }
    async signup(event) {
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
            const authenticatorResponse = await startRegistration({ optionsJSON: optionsResponseJson });
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });
            const attestationResponseJSON = await this._getAttestationResponse(authenticatorResponse);
            if (attestationResponseJSON !== false && this.creationSuccessRedirectUriValue) {
                window.location.replace(this.creationSuccessRedirectUriValue);
            }
        }
        catch (e) {
            this._dispatchEvent('webauthn:attestation:failure', { exception: e, assertionResponse: null });
            return;
        }
    }
    _dispatchEvent(name, payload) {
        this.element.dispatchEvent(new CustomEvent(name, { detail: payload, bubbles: true }));
    }
    _getData() {
        let data = new FormData();
        try {
            this.element.reportValidity();
            if (!this.element.checkValidity()) {
                return;
            }
            data = new FormData(this.element);
        }
        catch (e) {
        }
        function removeEmpty(obj) {
            return Object.entries(obj)
                .filter(([, v]) => v !== null && v !== '')
                .reduce((acc, [k, v]) => (Object.assign(Object.assign({}, acc), { [k]: v === Object(v) ? removeEmpty(v) : v })), {});
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
    async _getPublicKeyCredentialRequestOptions(formData) {
        return this._getOptions(this.requestOptionsUrlValue, formData);
    }
    async _getPublicKeyCredentialCreationOptions(formData) {
        return this._getOptions(this.creationOptionsUrlValue, formData);
    }
    async _getOptions(url, formData) {
        const data = formData || this._getData();
        if (!data) {
            return false;
        }
        this._dispatchEvent('webauthn:options:request', { data });
        const optionsResponse = await fetch(url, {
            headers: Object.assign({}, this.requestHeadersValue),
            method: 'POST',
            body: JSON.stringify(data)
        });
        if (!optionsResponse.ok) {
            this._dispatchEvent('webauthn:options:failure', { exception: null, optionsResponse });
            return false;
        }
        const options = await optionsResponse.json();
        this._dispatchEvent('webauthn:options:success', { data: options });
        return options;
    }
    async _getAttestationResponse(authenticatorResponse) {
        return this._getResult(this.creationResultUrlValue, 'webauthn:attestation:', authenticatorResponse);
    }
    async _getAssertionResponse(authenticatorResponse) {
        return this._getResult(this.requestResultUrlValue, 'webauthn:assertion:', authenticatorResponse);
    }
    async _getResult(url, eventPrefix, authenticatorResponse) {
        const attestationResponse = await fetch(url, {
            headers: Object.assign({}, this.requestHeadersValue),
            method: 'POST',
            body: JSON.stringify(authenticatorResponse)
        });
        if (!attestationResponse.ok) {
            this._dispatchEvent(eventPrefix + 'failure', {});
            return false;
        }
        const attestationResponseJSON = await attestationResponse.json();
        this._dispatchEvent(eventPrefix + 'success', { data: attestationResponseJSON });
        return attestationResponseJSON;
    }
}
default_1.values = {
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

export { default_1 as default };
