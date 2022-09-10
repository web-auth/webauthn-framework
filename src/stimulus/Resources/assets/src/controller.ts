'use strict';

import {Controller} from '@hotwired/stimulus';
import {startAuthentication, startRegistration} from '@simplewebauthn/browser';

export default class extends Controller {
    static values = {
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

    initialize() {
        this._dispatchEvent = this._dispatchEvent.bind(this);
        this._getData = this._getData.bind(this);
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

        this._dispatchEvent('webauthn:connect', {options});
    }

    async signin(event: Event) {
        event.preventDefault();
        const data = this._getData();
        const optionsHeaders = {
            'Content-Type': 'application/json',
        };
        this._dispatchEvent('webauthn:request:options', {data, headers: optionsHeaders});
        const resp = await fetch(this.requestOptionsUrlValue || '/request/options', {
            method: 'POST',
            headers: optionsHeaders,
            body: JSON.stringify(data),
        });
        const respJson = await resp.json();
        const asseResp = await startAuthentication(respJson);

        const responseHeaders = {
            'Content-Type': 'application/json',
        };

        this._dispatchEvent('webauthn:request:response', {response: asseResp, headers: responseHeaders});
        const verificationResp = await fetch(this.requestResultUrlValue || '/request', {
            method: 'POST',
            headers: responseHeaders,
            body: JSON.stringify(asseResp),
        });
        const verificationJSON = await verificationResp.json();

        if (verificationJSON && verificationJSON.errorMessage === '') {
            this._dispatchEvent('webauthn:request:success', verificationJSON);
            if (this.requestSuccessRedirectUriValue) {
                window.location.replace(this.requestSuccessRedirectUriValue);
            }
        } else {
            this._dispatchEvent('webauthn:request:failure', verificationJSON.errorMessage);
        }
    }

    async signup(event: Event) {
        event.preventDefault();
        const data = this._getData();
        const optionsHeaders = {
            'Content-Type': 'application/json',
        };
        this._dispatchEvent('webauthn:creation:options', {data, headers: optionsHeaders});
        const resp = await fetch(this.creationOptionsUrlValue || '/creation/options', {
            method: 'POST',
            headers: optionsHeaders,
            body: JSON.stringify(data),
        });

        const respJson = await resp.json();
        if (respJson.excludeCredentials === undefined) {
            respJson.excludeCredentials = [];
        }
        const attResp = await startRegistration(respJson);
        const responseHeaders = {
            'Content-Type': 'application/json',
        };
        this._dispatchEvent('webauthn:creation:response', {response: attResp, headers: responseHeaders});
        const verificationResp = await fetch(this.creationResultUrlValue || '/creation', {
            method: 'POST',
            headers: responseHeaders,
            body: JSON.stringify(attResp),
        });

        const verificationJSON = await verificationResp.json();
        if (verificationJSON && verificationJSON.errorMessage === '') {
            this._dispatchEvent('webauthn:creation:success', verificationJSON);
            if (this.creationSuccessRedirectUriValue) {
                window.location.replace(this.creationSuccessRedirectUriValue);
            }
        } else {
            this._dispatchEvent('webauthn:creation:failure', verificationJSON.errorMessage);
        }
    }

    _dispatchEvent(name: string, payload: any) {
        this.element.dispatchEvent(new CustomEvent(name, {detail: payload, bubbles: true}));
    }

    _getData() {
        let data = new FormData();
        try {
            data = new FormData(this.element);
        } catch (e) {
            //Nothing to do
        }

        function removeEmpty(obj) {
            return Object.entries(obj)
                .filter(([_, v]) => (v !== null && v !== ''))
                .reduce(
                    (acc, [k, v]) => ({...acc, [k]: v === Object(v) ? removeEmpty(v) : v}),
                    {}
                );
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
