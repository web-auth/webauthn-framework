'use strict';

import { Application } from '@hotwired/stimulus';
import { getByTestId, waitFor } from '@testing-library/dom';
import { clearDOM, mountDOM } from '@symfony/stimulus-testing';
import * as SimpleWebAuthnBrowser from '@simplewebauthn/browser';
import PaymentController from '../src/payment-controller';

jest.mock('@simplewebauthn/browser');

const startStimulus = () => {
    const application = Application.start();
    application.register('webauthn--payment', PaymentController);
    return application;
};

const submitForm = (form) => {
    const submitEvent = new Event('submit', {
        bubbles: true,
        cancelable: true,
    });
    form.dispatchEvent(submitEvent);
};

describe('PaymentController', () => {
    let container;
    let fetchMock;
    let application;

    beforeEach(() => {
        container = mountDOM(`
            <html lang="en">
                <head><title>SPC Test</title></head>
                <body>
                    <form
                        data-testid="payment-form"
                        data-controller="webauthn--payment"
                        data-action="submit->webauthn--payment#authenticate"
                        data-webauthn--payment-options-url-value="/payment/options"
                        data-webauthn--payment-result-url-value="/payment/verify"
                    >
                        <input type="hidden" data-webauthn--payment-target="result">
                        <button type="submit">Pay</button>
                    </form>
                </body>
            </html>
        `);

        fetchMock = jest.fn();
        globalThis.fetch = fetchMock;

        SimpleWebAuthnBrowser.browserSupportsWebAuthn.mockReturnValue(true);
        SimpleWebAuthnBrowser.browserSupportsWebAuthnAutofill.mockResolvedValue(false);
        SimpleWebAuthnBrowser.platformAuthenticatorIsAvailable.mockResolvedValue(true);
        SimpleWebAuthnBrowser.bufferToBase64URLString.mockImplementation((buf) => {
            const bytes = new Uint8Array(buf);
            return Buffer.from(bytes).toString('base64url');
        });
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

    it('starts an SPC ceremony with the payment extension passed unchanged', async () => {
        const form = getByTestId(container, 'payment-form');
        const paymentOptions = {
            challenge: 'test-challenge',
            rpId: 'example.com',
            extensions: {
                payment: {
                    isPayment: true,
                    rpId: 'example.com',
                    topOrigin: 'https://merchant.example.com',
                    total: { currency: 'USD', value: '99.99' },
                    instrument: {
                        displayName: 'Visa •••• 1234',
                        icon: 'https://example.com/visa-icon.png',
                    },
                    payeeName: 'Merchant Store',
                    payeeOrigin: 'https://merchant.example.com',
                },
            },
        };
        const mockCredential = {
            id: 'cred',
            rawId: 'raw',
            response: { clientDataJSON: 'data', authenticatorData: 'auth', signature: 'sig' },
            type: 'public-key',
            clientExtensionResults: {},
        };

        fetchMock
            .mockResolvedValueOnce({ ok: true, json: async () => paymentOptions })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

        SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue(mockCredential);

        application = startStimulus();
        await waitFor(() => expect(form).toBeTruthy());
        submitForm(form);

        await waitFor(() => {
            expect(SimpleWebAuthnBrowser.startAuthentication).toHaveBeenCalledTimes(1);
        });
        const passedOptions = SimpleWebAuthnBrowser.startAuthentication.mock.calls[0][0].optionsJSON;
        expect(passedOptions.extensions.payment.isPayment).toBe(true);
        expect(passedOptions.extensions.payment.total.value).toBe('99.99');
        expect(passedOptions.extensions.payment.instrument.displayName).toBe('Visa •••• 1234');
    });

    it('encodes browserBoundSignature ArrayBuffer to base64url for transport', async () => {
        const form = getByTestId(container, 'payment-form');
        const signatureBytes = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]).buffer; // "hello"
        const mockCredential = {
            id: 'cred',
            rawId: 'raw',
            response: { clientDataJSON: 'data', authenticatorData: 'auth', signature: 'sig' },
            type: 'public-key',
            clientExtensionResults: {
                payment: {
                    browserBoundSignature: { signature: signatureBytes },
                },
            },
        };

        fetchMock
            .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'c' }) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });
        SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue(mockCredential);

        let credentialEvent = null;
        form.addEventListener('webauthn:authentication:credential', (e) => {
            credentialEvent = e.detail;
        });

        application = startStimulus();
        await waitFor(() => expect(form).toBeTruthy());
        submitForm(form);

        await waitFor(() => expect(credentialEvent).not.toBeNull());

        const transportedSignature =
            credentialEvent.credential.clientExtensionResults.payment.browserBoundSignature.signature;
        expect(typeof transportedSignature).toBe('string');
        expect(transportedSignature).toBe('aGVsbG8'); // base64url("hello")
    });

    it('passes through credentials that have no payment extension result', async () => {
        const form = getByTestId(container, 'payment-form');
        const mockCredential = {
            id: 'cred',
            rawId: 'raw',
            response: { clientDataJSON: 'data', authenticatorData: 'auth', signature: 'sig' },
            type: 'public-key',
            clientExtensionResults: {},
        };

        fetchMock
            .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'c' }) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });
        SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue(mockCredential);

        let credentialEvent = null;
        form.addEventListener('webauthn:authentication:credential', (e) => {
            credentialEvent = e.detail;
        });

        application = startStimulus();
        await waitFor(() => expect(form).toBeTruthy());
        submitForm(form);

        await waitFor(() => expect(credentialEvent).not.toBeNull());
        expect(credentialEvent.credential.clientExtensionResults.payment).toBeUndefined();
    });

    describe('SPC on the native L3 path', () => {
        // The W3C SPC `payment` extension is not part of WebAuthn L3, so
        // PublicKeyCredential.toJSON() may leave its
        // `browserBoundSignature.signature` as an ArrayBuffer. The base
        // controller must therefore call _processExtensionsOutput on the
        // native path so this subclass override still runs.

        let originalPublicKeyCredential;
        let originalNavigator;

        beforeEach(() => {
            originalPublicKeyCredential = globalThis.PublicKeyCredential;
            originalNavigator = globalThis.navigator;
        });

        afterEach(() => {
            if (originalPublicKeyCredential === undefined) {
                delete globalThis.PublicKeyCredential;
            } else {
                Object.defineProperty(globalThis, 'PublicKeyCredential', {
                    value: originalPublicKeyCredential,
                    configurable: true,
                });
            }
            if (originalNavigator) {
                Object.defineProperty(globalThis, 'navigator', {
                    value: originalNavigator,
                    configurable: true,
                });
            }
        });

        it('still encodes browserBoundSignature ArrayBuffer when the native helpers are used', async () => {
            const form = getByTestId(container, 'payment-form');
            const signatureBytes = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]).buffer;
            const credentialJson = {
                id: 'cred',
                rawId: 'raw',
                response: { clientDataJSON: 'data', authenticatorData: 'auth', signature: 'sig' },
                type: 'public-key',
                clientExtensionResults: {
                    payment: { browserBoundSignature: { signature: signatureBytes } },
                },
            };

            Object.defineProperty(globalThis, 'PublicKeyCredential', {
                value: {
                    parseCreationOptionsFromJSON: jest.fn(),
                    parseRequestOptionsFromJSON: (json) => json,
                },
                configurable: true,
            });
            const getMock = jest.fn().mockResolvedValue({ toJSON: () => credentialJson });
            Object.defineProperty(globalThis, 'navigator', {
                value: { credentials: { get: getMock } },
                configurable: true,
            });
            SimpleWebAuthnBrowser.WebAuthnAbortService.createNewAbortSignal = jest.fn(
                () => new AbortController().signal
            );

            fetchMock
                .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'c' }) })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            let credentialEvent = null;
            form.addEventListener('webauthn:authentication:credential', (e) => {
                credentialEvent = e.detail;
            });

            application = startStimulus();
            await waitFor(() => expect(form).toBeTruthy());
            submitForm(form);

            await waitFor(() => expect(credentialEvent).not.toBeNull());

            expect(getMock).toHaveBeenCalledTimes(1);
            expect(SimpleWebAuthnBrowser.startAuthentication).not.toHaveBeenCalled();
            const transportedSignature =
                credentialEvent.credential.clientExtensionResults.payment.browserBoundSignature.signature;
            expect(typeof transportedSignature).toBe('string');
            expect(transportedSignature).toBe('aGVsbG8');
        });
    });
});
