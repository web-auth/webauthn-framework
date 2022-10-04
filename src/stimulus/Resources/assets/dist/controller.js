import { Controller } from '@hotwired/stimulus';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

class default_1 extends Controller {
    initialize() {
        this._dispatchEvent = this._dispatchEvent.bind(this);
        this._getData = this._getData.bind(this);
        this.fetch = this.fetch.bind(this);
    }
    connect() {
        const options = {
            requestResultUrl: this.requestResultUrl || '/request',
            requestOptionsUrl: this.requestOptionsUrl || '/request/options',
            requestSuccessRedirectUri: this.requestSuccessRedirectUri || null,
            creationResultUrl: this.creationResultUrl || '/creation',
            creationOptionsUrl: this.creationOptionsUrl || '/creation/options',
            creationSuccessRedirectUri: this.creationSuccessRedirectUri || null,
        };
        this._dispatchEvent('webauthn:connect', { options });
    }
    async signin(event) {
        event.preventDefault();
        const data = this._getData();
        this._dispatchEvent('webauthn:request:options', { data });
        const resp = await this.fetch('POST', this.requestOptionsUrlValue || '/request/options', JSON.stringify(data));
        const respJson = await resp.response;
        const asseResp = await startAuthentication(respJson);
        const verificationResp = await this.fetch('POST', this.requestResultUrlValue || '/request', JSON.stringify(asseResp));
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
        const resp = await this.fetch('POST', this.creationOptionsUrlValue || '/creation/options', JSON.stringify(data));
        const respJson = await resp.response;
        if (respJson.excludeCredentials === undefined) {
            respJson.excludeCredentials = [];
        }
        const attResp = await startRegistration(respJson);
        this._dispatchEvent('webauthn:creation:response', { response: attResp });
        const verificationResp = await this.fetch('POST', this.creationResultUrlValue || '/creation', JSON.stringify(attResp));
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
            xhr.responseType = "json";
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.onload = function () {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve(xhr);
                }
                else {
                    reject({
                        status: xhr.status,
                        statusText: xhr.statusText
                    });
                }
            };
            xhr.onerror = function () {
                reject({
                    status: xhr.status,
                    statusText: xhr.statusText
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
                .filter(([_, v]) => (v !== null && v !== ''))
                .reduce((acc, [k, v]) => (Object.assign(Object.assign({}, acc), { [k]: v === Object(v) ? removeEmpty(v) : v })), {});
        }
        return removeEmpty({
            username: data.get(this.usernameField || 'username'),
            displayName: data.get(this.displayNameField || 'displayName'),
            attestation: data.get(this.attestationField || 'attestation'),
            userVerification: data.get(this.userVerificationField || 'userVerification'),
            residentKey: data.get(this.residentKeyField || 'residentKey'),
            requireResidentKey: data.get(this.requireResidentKeyField || 'requireResidentKey'),
            authenticatorAttachment: data.get(this.authenticatorAttachmentField || 'authenticatorAttachment'),
        });
    }
}
default_1.values = {
    requestResultUrl: String,
    requestOptionsUrl: String,
    requestSuccessRedirectUri: String,
    creationResultUrl: String,
    creationOptionsUrl: String,
    creationSuccessRedirectUri: String,
    usernameField: String,
    displayNameField: String,
    attestationField: String,
    userVerificationField: String,
    residentKeyField: String,
    requireResidentKeyField: String,
    authenticatorAttachmentField: String,
};

export { default_1 as default };
