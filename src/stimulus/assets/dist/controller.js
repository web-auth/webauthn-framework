import { Controller } from '@hotwired/stimulus';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

class default_1 extends Controller {
    connect() {
        var _a, _b;
        const options = {
            requestResultUrl: this.requestResultUrlValue,
            requestOptionsUrl: this.requestOptionsUrlValue,
            requestSuccessRedirectUri: (_a = this.requestSuccessRedirectUriValue) !== null && _a !== void 0 ? _a : null,
            creationResultUrl: this.creationResultUrlValue,
            creationOptionsUrl: this.creationOptionsUrlValue,
            creationSuccessRedirectUri: (_b = this.creationSuccessRedirectUriValue) !== null && _b !== void 0 ? _b : null,
        };
        this._dispatchEvent('webauthn:connect', { options });
    }
    async signin(event) {
        event.preventDefault();
        const data = this._getData();
        this._dispatchEvent('webauthn:request:options', { data });
        const resp = await this.fetch('POST', this.requestOptionsUrlValue, JSON.stringify(data));
        const respJson = await resp.response;
        const asseResp = await startAuthentication(respJson, this.useBrowserAutofillValue);
        const verificationResp = await this.fetch('POST', this.requestResultUrlValue, JSON.stringify(asseResp));
        const verificationJSON = await verificationResp.response;
        this._dispatchEvent('webauthn:request:response', { response: asseResp });
        if (verificationJSON && verificationJSON.errorMessage === '') {
            this._dispatchEvent('webauthn:request:success', verificationJSON);
            if (this.requestSuccessRedirectUriValue) {
                window.location.replace(this.requestSuccessRedirectUriValue);
            }
        }
        else {
            this._dispatchEvent('webauthn:request:failure', verificationJSON.errorMessage);
        }
    }
    async signup(event) {
        event.preventDefault();
        const data = this._getData();
        this._dispatchEvent('webauthn:creation:options', { data });
        const resp = await this.fetch('POST', this.creationOptionsUrlValue, JSON.stringify(data));
        const respJson = await resp.response;
        if (respJson.excludeCredentials === undefined) {
            respJson.excludeCredentials = [];
        }
        const attResp = await startRegistration(respJson);
        this._dispatchEvent('webauthn:creation:response', { response: attResp });
        const verificationResp = await this.fetch('POST', this.creationResultUrlValue, JSON.stringify(attResp));
        const verificationJSON = await verificationResp.response;
        if (verificationJSON && verificationJSON.errorMessage === '') {
            this._dispatchEvent('webauthn:creation:success', verificationJSON);
            if (this.creationSuccessRedirectUriValue) {
                window.location.replace(this.creationSuccessRedirectUriValue);
            }
        }
        else {
            this._dispatchEvent('webauthn:creation:failure', verificationJSON.errorMessage);
        }
    }
    _dispatchEvent(name, payload) {
        this.element.dispatchEvent(new CustomEvent(name, { detail: payload, bubbles: true }));
    }
    fetch(method, url, body) {
        return new Promise(function (resolve, reject) {
            const xhr = new XMLHttpRequest();
            xhr.open(method, url);
            xhr.responseType = 'json';
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.onload = function () {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve(xhr);
                }
                else {
                    reject({
                        status: xhr.status,
                        statusText: xhr.statusText,
                    });
                }
            };
            xhr.onerror = function () {
                reject({
                    status: xhr.status,
                    statusText: xhr.statusText,
                });
            };
            xhr.send(body);
        });
    }
    _getData() {
        let data = new FormData();
        try {
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
            requireResidentKey: data.get(this.requireResidentKeyFieldValue),
            authenticatorAttachment: data.get(this.authenticatorAttachmentFieldValue),
        });
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
    requireResidentKeyField: { type: String, default: 'requireResidentKey' },
    authenticatorAttachmentField: { type: String, default: 'authenticatorAttachment' },
    useBrowserAutofill: { type: Boolean, default: false },
};

export { default_1 as default };
