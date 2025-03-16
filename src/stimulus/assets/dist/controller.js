import { Controller } from '@hotwired/stimulus';
import { browserSupportsWebAuthnAutofill, browserSupportsWebAuthn, startAuthentication, startRegistration, base64URLStringToBuffer, bufferToBase64URLString } from '@simplewebauthn/browser';

class default_1 extends Controller {
    constructor() {
        super(...arguments);
        this.connect = async () => {
            var _a, _b, _c, _d;
            const options = {
                requestResultUrl: this.requestResultUrlValue,
                requestOptionsUrl: this.requestOptionsUrlValue,
                requestResultField: (_a = this.requestResultFieldValue) !== null && _a !== undefined ? _a : null,
                creationResultField: (_b = this.creationResultFieldValue) !== null && _b !== undefined ? _b : null,
                requestSuccessRedirectUri: (_c = this.requestSuccessRedirectUriValue) !== null && _c !== undefined ? _c : null,
                creationResultUrl: this.creationResultUrlValue,
                creationOptionsUrl: this.creationOptionsUrlValue,
                creationSuccessRedirectUri: (_d = this.creationSuccessRedirectUriValue) !== null && _d !== undefined ? _d : null,
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
        var _a;
        try {
            optionsResponseJson = this._processExtensionsInput(optionsResponseJson);
            let authenticatorResponse = await startAuthentication({ optionsJSON: optionsResponseJson, useBrowserAutofill });
            authenticatorResponse = this._processExtensionsOutput(authenticatorResponse);
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });
            if (this.requestResultFieldValue && this.element instanceof HTMLFormElement) {
                (_a = this.element.querySelector(this.requestResultFieldValue)) === null || _a === void 0 ? void 0 : _a.setAttribute('value', JSON.stringify(authenticatorResponse));
                this.element.submit();
                return;
            }
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
        var _a;
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
            let authenticatorResponse = await startRegistration({ optionsJSON: optionsResponseJson });
            authenticatorResponse = this._processExtensionsOutput(authenticatorResponse);
            this._dispatchEvent('webauthn:authenticator:response', { response: authenticatorResponse });
            if (this.creationResultFieldValue && this.element instanceof HTMLFormElement) {
                (_a = this.element.querySelector(this.creationResultFieldValue)) === null || _a === void 0 ? void 0 : _a.setAttribute('value', JSON.stringify(authenticatorResponse));
                this.element.submit();
                return;
            }
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
    _processExtensionsInput(options) {
        if (!options || !options.extensions) {
            return options;
        }
        if (options.extensions.prf) {
            options.extensions.prf = this._processPrfInput(options.extensions.prf);
        }
        return options;
    }
    _processPrfInput(prf) {
        if (prf.eval) {
            prf.eval = this._importPrfValues(eval);
        }
        if (prf.evalByCredential) {
            Object.keys(prf.evalByCredential).forEach((key) => {
                prf.evalByCredential[key] = this._importPrfValues(prf.evalByCredential[key]);
            });
        }
        return prf;
    }
    _importPrfValues(values) {
        values.first = base64URLStringToBuffer(values.first);
        if (values.second) {
            values.second = base64URLStringToBuffer(values.second);
        }
        return values;
    }
    _processExtensionsOutput(options) {
        if (!options || !options.extensions) {
            return options;
        }
        if (options.extensions.prf) {
            options.extensions.prf = this._processPrfOutput(options.extensions.prf);
        }
        return options;
    }
    _processPrfOutput(prf) {
        if (!prf.result) {
            return prf;
        }
        prf.result = this._exportPrfValues(prf.result);
        return prf;
    }
    _exportPrfValues(values) {
        values.first = bufferToBase64URLString(values.first);
        if (values.second) {
            values.second = bufferToBase64URLString(values.second);
        }
        return values;
    }
}
default_1.values = {
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

export { default_1 as default };
