'use strict';

import { Application, Controller } from '@hotwired/stimulus';
import { getByTestId, waitFor } from '@testing-library/dom';
import { clearDOM, mountDOM } from '@symfony/stimulus-testing';
import * as SimpleWebAuthnBrowser from '@simplewebauthn/browser';
import WebauthnController from '../src/controller';

jest.mock('@simplewebauthn/browser', () => {
    const actual = jest.requireActual('@simplewebauthn/browser');
    return {
        ...actual,
        browserSupportsWebAuthn: jest.fn(),
        browserSupportsWebAuthnAutofill: jest.fn(),
        startAuthentication: jest.fn(),
        startRegistration: jest.fn(),
    };
});

// Controller used to check the actual controller was properly booted
class CheckController extends Controller {
    connect() {
        this.element.addEventListener('webauthn:connect', () => {
            this.element.classList.add('connected');
        });
    }
}

const startStimulus = () => {
    const application = Application.start();
    application.register('check', CheckController);
    application.register('webauthn', WebauthnController);
    return application;
};

describe('WebauthnController', () => {
    let container;
    let application;

    beforeEach(() => {
        container = mountDOM(`
            <html lang="en">
                <head>
                    <title>Symfony UX</title>
                </head>
                <body>
                    <form
                        data-testid="webauthn"
                        data-controller="check webauthn"
                    >
                    </form>
                </body>
            </html>
        `);
    });

    afterEach(() => {
        if (application) {
            application.stop();
            application = null;
        }
        clearDOM();
    });

    it('connect', async () => {
        expect(getByTestId(container, 'webauthn')).not.toHaveClass('connected');

        application = startStimulus();
        await waitFor(() => expect(getByTestId(container, 'webauthn')).toHaveClass('connected'));
    });
});

describe('WebauthnController client extension results', () => {
    const prfFirst = new Uint8Array([1, 2, 3]).buffer;
    const prfSecond = new Uint8Array([4, 5, 6]).buffer;
    let application;
    let fetchMock;

    const mountForm = (attributes, fields = '') =>
        getByTestId(
            mountDOM(`
                <form data-testid="legacy-form" data-controller="webauthn" ${attributes}>
                    <input type="text" name="username" value="john">
                    ${fields}
                </form>
            `),
            'legacy-form'
        );

    const startAndSubmit = async (form) => {
        const connected = new Promise((resolve) => {
            form.addEventListener('webauthn:connect', resolve, { once: true });
        });
        application = startStimulus();
        await connected;
        form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    };

    const listenToResponse = (form) => {
        const responses = [];
        form.addEventListener('webauthn:authenticator:response', (e) => {
            responses.push(e.detail.response);
        });
        return responses;
    };

    beforeEach(() => {
        fetchMock = jest.fn();
        globalThis.fetch = fetchMock;
        SimpleWebAuthnBrowser.browserSupportsWebAuthn.mockReturnValue(true);
        SimpleWebAuthnBrowser.browserSupportsWebAuthnAutofill.mockResolvedValue(false);
    });

    afterEach(() => {
        if (application) {
            application.stop();
            application = null;
        }
        clearDOM();
        jest.clearAllMocks();
        delete globalThis.fetch;
    });

    it('sends the browser-bound signature of an assertion as a base64url string', async () => {
        const form = mountForm(
            'data-action="submit->webauthn#signin" data-webauthn-request-result-url-value="/request"'
        );

        fetchMock
            .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test' }) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });
        SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: {
                payment: {
                    browserBoundSignature: { signature: new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]).buffer },
                },
            },
        });

        await startAndSubmit(form);

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });

        const [url, request] = fetchMock.mock.calls[1];
        expect(url).toBe('/request');
        expect(JSON.parse(request.body).clientExtensionResults).toEqual({
            payment: { browserBoundSignature: { signature: 'aGVsbG8' } },
        });
    });

    it('sends the browser-bound signature of a registration as a base64url string', async () => {
        const form = mountForm(
            'data-action="submit->webauthn#signup" data-webauthn-creation-result-url-value="/creation"'
        );

        fetchMock
            .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test', rp: {}, user: {} }) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });
        SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: {
                credProps: { rk: true },
                payment: {
                    browserBoundSignature: { signature: new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]).buffer },
                },
            },
        });

        await startAndSubmit(form);

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });

        const [url, request] = fetchMock.mock.calls[1];
        expect(url).toBe('/creation');
        expect(JSON.parse(request.body).clientExtensionResults).toEqual({
            credProps: { rk: true },
            payment: { browserBoundSignature: { signature: 'aGVsbG8' } },
        });
    });

    it('keeps the PRF results out of the assertion request', async () => {
        const form = mountForm(
            'data-action="submit->webauthn#signin" data-webauthn-request-result-url-value="/request"'
        );
        const responses = listenToResponse(form);

        fetchMock
            .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test' }) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });
        SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: { prf: { results: { first: prfFirst, second: prfSecond } } },
        });

        await startAndSubmit(form);

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });

        const [url, request] = fetchMock.mock.calls[1];
        expect(url).toBe('/request');
        expect(JSON.parse(request.body)).toEqual({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: { prf: {} },
        });
        expect(responses[0].clientExtensionResults.prf.results).toEqual({ first: 'AQID', second: 'BAUG' });
    });

    it('keeps the PRF results out of the assertion result field', async () => {
        const form = mountForm(
            'data-action="submit->webauthn#signin" data-webauthn-request-result-field-value="input[name=credential]"',
            '<input type="hidden" name="credential">'
        );
        const responses = listenToResponse(form);
        const submitSpy = jest.spyOn(form, 'submit').mockImplementation(() => {});

        fetchMock.mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test' }) });
        SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: { prf: { results: { first: prfFirst } } },
        });

        await startAndSubmit(form);

        await waitFor(() => {
            expect(submitSpy).toHaveBeenCalled();
        });

        expect(JSON.parse(form.querySelector('input[name="credential"]').getAttribute('value'))).toEqual({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: { prf: {} },
        });
        expect(responses[0].clientExtensionResults.prf.results).toEqual({ first: 'AQID' });
    });

    it('keeps the PRF results out of the attestation request', async () => {
        const form = mountForm(
            'data-action="submit->webauthn#signup" data-webauthn-creation-result-url-value="/creation"'
        );
        const responses = listenToResponse(form);

        fetchMock
            .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test', rp: {}, user: {} }) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });
        SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: {
                credProps: { rk: true },
                prf: { enabled: true, results: { first: prfFirst, second: prfSecond } },
            },
        });

        await startAndSubmit(form);

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });

        const [url, request] = fetchMock.mock.calls[1];
        expect(url).toBe('/creation');
        expect(JSON.parse(request.body)).toEqual({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: { credProps: { rk: true }, prf: { enabled: true } },
        });
        expect(responses[0].clientExtensionResults.prf).toEqual({
            enabled: true,
            results: { first: 'AQID', second: 'BAUG' },
        });
    });

    it('keeps the PRF results out of the attestation result field', async () => {
        const form = mountForm(
            'data-action="submit->webauthn#signup" data-webauthn-creation-result-field-value="input[name=credential]"',
            '<input type="hidden" name="credential">'
        );
        const responses = listenToResponse(form);
        const submitSpy = jest.spyOn(form, 'submit').mockImplementation(() => {});

        fetchMock.mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test', rp: {}, user: {} }) });
        SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: { prf: { enabled: true, results: { first: prfFirst } } },
        });

        await startAndSubmit(form);

        await waitFor(() => {
            expect(submitSpy).toHaveBeenCalled();
        });

        expect(JSON.parse(form.querySelector('input[name="credential"]').getAttribute('value'))).toEqual({
            id: 'credential-id',
            type: 'public-key',
            clientExtensionResults: { prf: { enabled: true } },
        });
        expect(responses[0].clientExtensionResults.prf).toEqual({ enabled: true, results: { first: 'AQID' } });
    });
});
