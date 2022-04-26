'use strict';

import { Controller } from '@hotwired/stimulus';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

export default class extends Controller {
    static values = {
        requestResultUrl: String,
        requestOptionsUrl: String,
        requestSuccessRedirectUri: String,
        creationResultUrl: String,
        creationOptionsUrl: String,
        creationSuccessRedirectUri: String,
    };

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

    async signin(event: Event) {
        event.preventDefault();
        const data = this._getData();
        const resp = await fetch(this.requestOptionsUrlValue || '/request/options', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

        const asseResp = await startAuthentication(await resp.json());

        const verificationResp = await fetch(this.requestResultUrlValue || '/request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(asseResp),
        });

        const verificationJSON = await verificationResp.json();
        if (verificationJSON && verificationJSON.errorMessage === '') {
            this._dispatchEvent('webauthn:request:success', verificationJSON);
            if (this.requestSuccessRedirectUriValue) {
                window.location.replace(this.requestSuccessRedirectUriValue);
            }
        } else {
            console.log(`Oh no, something went wrong! Response: <pre>${JSON.stringify(verificationJSON)}</pre>`);
            this._dispatchEvent('webauthn:request:failure', verificationJSON.errorMessage);
        }
    }

    async signup(event: Event) {
        event.preventDefault();
        const data = this._getData();
        const resp = await fetch(this.creationOptionsUrlValue || '/creation/options', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

        const attResp = await startRegistration(await resp.json());
        const verificationResp = await fetch(this.creationResultUrlValue || '/creation', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(attResp),
        });

        const verificationJSON = await verificationResp.json();
        if (verificationJSON && verificationJSON.errorMessage === '') {
            this._dispatchEvent('webauthn:creation:success', verificationJSON);
            if (this.creationSuccessRedirectUriValue) {
                window.location.replace(this.creationSuccessRedirectUriValue);
            }
        } else {
            console.log(`Oh no, something went wrong! Response: <pre>${JSON.stringify(verificationJSON)}</pre>`);
            this._dispatchEvent('webauthn:creation:failure', verificationJSON.errorMessage);
        }
    }

    _dispatchEvent(name: string, payload: any) {
        this.element.dispatchEvent(new CustomEvent(name, { detail: payload, bubbles: true }));
    }

    _getData() {
        let data = new FormData();
        try {
            data = new FormData(this.element);
        } catch (e) {
            //Nothing to do
        }
        const object = {};
        data.forEach((value: FormDataEntryValue, key: string) => {
            if (value !== '') {
                object[key] = value;
            }
        });

        return object;
    }
}
