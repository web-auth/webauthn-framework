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
    }

    async signin(event: Event) {
        event.preventDefault();
        const data = this._getData();

        const resp = await this.fetch('POST', this.requestOptionsUrlValue || '/request/options', JSON.stringify(data));
        const respJson = await resp.response;
        const asseResp = await startAuthentication(respJson);

        const verificationResp = await this.fetch('POST', this.requestResultUrlValue || '/request', JSON.stringify(asseResp));
        const verificationJSON = await verificationResp.response;

        if (verificationJSON && verificationJSON.errorMessage === '') {
            if (this.requestSuccessRedirectUriValue) {
                window.location.replace(this.requestSuccessRedirectUriValue);
            }
        } else {
            alert('Something bad happens :( - '+verificationJSON.errorMessage);
        }
    }

    async signup(event: Event) {
        event.preventDefault();
        const data = this._getData();
        const resp = await this.fetch('POST', this.creationOptionsUrlValue || '/creation/options', JSON.stringify(data));

        const respJson = await resp.response;
        if (respJson.excludeCredentials === undefined) {
            respJson.excludeCredentials = [];
        }
        const attResp = await startRegistration(respJson);
        const verificationResp = await this.fetch('POST', this.creationResultUrlValue || '/creation', JSON.stringify(attResp));

        const verificationJSON = await verificationResp.response;
        if (verificationJSON && verificationJSON.errorMessage === '') {
            if (this.creationSuccessRedirectUriValue) {
                window.location.replace(this.creationSuccessRedirectUriValue);
            }
        } else {
            alert('Something bad happens :( - '+verificationJSON.errorMessage);
        }
    }

    fetch (method: string, url: string, body: string): Promise<XMLHttpRequest> {
        return new Promise(function (resolve, reject) {
            const xhr = new XMLHttpRequest();
            xhr.open(method, url);
            xhr.responseType = "json";
            xhr.setRequestHeader('Content-Type', 'application/json')
            xhr.onload = function () {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve(xhr);
                } else {
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
