'use strict';

import { Application } from '@hotwired/stimulus';
import { getByTestId, waitFor } from '@testing-library/dom';
import { clearDOM, mountDOM } from '@symfony/stimulus-testing';
import * as SimpleWebAuthnBrowser from '@simplewebauthn/browser';
import RegistrationController from '../src/registration-controller';

// Mock @simplewebauthn/browser but keep base64 helpers + WebAuthnError real so PRF
// processing in BaseController and `instanceof WebAuthnError` checks behave normally.
jest.mock('@simplewebauthn/browser', () => {
    const actual = jest.requireActual('@simplewebauthn/browser');
    return {
        ...actual,
        browserSupportsWebAuthn: jest.fn(),
        platformAuthenticatorIsAvailable: jest.fn(),
        startRegistration: jest.fn(),
        WebAuthnAbortService: {
            cancelCeremony: jest.fn(),
            createNewAbortSignal: jest.fn(() => new AbortController().signal),
        },
    };
});

const startStimulus = () => {
    const application = Application.start();
    application.register('webauthn--registration', RegistrationController);
    return application;
};

const submitForm = (form) => {
    const submitEvent = new Event('submit', {
        bubbles: true,
        cancelable: true,
    });
    form.dispatchEvent(submitEvent);
};

const waitForConnection = (form) => {
    return new Promise((resolve) => {
        form.addEventListener('webauthn:registration:connect', resolve, { once: true });
    });
};

describe('RegistrationController', () => {
    let container;
    let fetchMock;
    let application;

    beforeEach(() => {
        container = mountDOM(`
            <html lang="en">
                <head>
                    <title>WebAuthn Registration Test</title>
                </head>
                <body>
                    <form
                        data-testid="registration-form"
                        data-controller="webauthn--registration"
                        data-action="submit->webauthn--registration#register"
                        data-webauthn--registration-options-url-value="/register/options"
                        data-webauthn--registration-result-url-value="/register/verify"
                    >
                        <input type="text" name="username" value="newuser" data-webauthn--registration-target="username">
                        <select name="attestation" data-webauthn--registration-target="attestation">
                            <option value="none">None</option>
                            <option value="direct">Direct</option>
                        </select>
                        <input type="hidden" data-webauthn--registration-target="result">
                        <button type="submit">Register</button>
                    </form>
                </body>
            </html>
        `);

        // Mock fetch globally
        fetchMock = jest.fn();
        globalThis.fetch = fetchMock;

        // Default mocks
        SimpleWebAuthnBrowser.browserSupportsWebAuthn.mockReturnValue(true);
        SimpleWebAuthnBrowser.platformAuthenticatorIsAvailable.mockResolvedValue(true);
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

    describe('Connection and initialization', () => {
        it('connects and dispatches event', async () => {
            let eventDispatched = false;
            const form = getByTestId(container, 'registration-form');

            form.addEventListener('webauthn:registration:connect', () => {
                eventDispatched = true;
            });

            application = startStimulus();

            await waitFor(() => expect(eventDispatched).toBe(true));
        });

        it('has correct target elements', async () => {
            application = startStimulus();
            const form = getByTestId(container, 'registration-form');

            await waitFor(() => {
                const usernameInput = form.querySelector('[data-webauthn--registration-target="username"]');
                const attestationSelect = form.querySelector('[data-webauthn--registration-target="attestation"]');
                const resultInput = form.querySelector('[data-webauthn--registration-target="result"]');

                expect(usernameInput).toBeTruthy();
                expect(attestationSelect).toBeTruthy();
                expect(resultInput).toBeTruthy();
            });
        });
    });

    describe('Successful registration', () => {
        it('registers successfully with API verification', async () => {
            const form = getByTestId(container, 'registration-form');
            const mockOptions = {
                challenge: 'test-challenge',
                rp: { name: 'Test RP', id: 'example.com' },
                user: { id: 'user-id', name: 'newuser', displayName: 'New User' },
                pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            };
            const mockCredential = {
                id: 'credential-id',
                rawId: 'credential-raw-id',
                response: {
                    clientDataJSON: 'data',
                    attestationObject: 'attestation',
                    transports: ['usb', 'nfc'],
                },
                type: 'public-key',
            };
            const mockVerification = { verified: true, registrationInfo: {} };

            let credentialEvent = null;
            form.addEventListener('webauthn:registration:credential', (e) => {
                credentialEvent = e.detail;
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => mockOptions,
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => mockVerification,
                });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue(mockCredential);

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(fetchMock).toHaveBeenCalledTimes(2);
                expect(credentialEvent).toBeTruthy();
                expect(credentialEvent.credential).toEqual(mockCredential);
            });
        });

        it('registers successfully with form submission', async () => {
            container = mountDOM(`
                <form
                    data-testid="form-submit"
                    data-controller="webauthn--registration"
                    data-action="submit->webauthn--registration#register"
                    data-webauthn--registration-options-url-value="/register/options"
                    data-webauthn--registration-submit-via-form-value="true"
                >
                    <input type="text" name="username" value="newuser">
                    <input type="hidden" data-webauthn--registration-target="result">
                    <button type="submit">Register</button>
                </form>
            `);

            const form = getByTestId(container, 'form-submit');
            const mockCredential = { id: 'credential-id', type: 'public-key' };

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test', rp: {}, user: {} }),
            });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue(mockCredential);

            const submitSpy = jest.spyOn(form, 'submit').mockImplementation(() => {});

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                const resultInput = form.querySelector('[data-webauthn--registration-target="result"]');
                expect(resultInput.value).toBe(JSON.stringify(mockCredential));
                expect(submitSpy).toHaveBeenCalled();
            });
        });

        it('redirects on successful registration when configured', async () => {
            container = mountDOM(`
                <form
                    data-testid="redirect-form"
                    data-controller="webauthn--registration"
                    data-action="submit->webauthn--registration#register"
                    data-webauthn--registration-options-url-value="/register/options"
                    data-webauthn--registration-result-url-value="/register/verify"
                    data-webauthn--registration-success-redirect-uri-value="/profile"
                >
                    <input type="text" name="username" value="newuser">
                    <button type="submit">Register</button>
                </form>
            `);

            // jsdom marks window.location as non-configurable. The
            // controller exposes _redirect() so tests can spy on it on the
            // prototype without fighting jsdom.
            const redirectSpy = jest.spyOn(RegistrationController.prototype, '_redirect').mockImplementation(() => {});

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test', rp: {}, user: {} }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ verified: true }),
                });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({ id: 'cred' });

            const form = getByTestId(container, 'redirect-form');
            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            try {
                await waitFor(() => {
                    expect(redirectSpy).toHaveBeenCalledWith('/profile');
                });
            } finally {
                redirectSpy.mockRestore();
            }
        });

        it('sends all registration parameters', async () => {
            container = mountDOM(`
                <form
                    data-testid="full-params-form"
                    data-controller="webauthn--registration"
                    data-action="submit->webauthn--registration#register"
                    data-webauthn--registration-options-url-value="/register/options"
                    data-webauthn--registration-result-url-value="/register/verify"
                >
                    <input type="text" name="username" value="testuser" data-webauthn--registration-target="username">
                    <select name="attestation" data-webauthn--registration-target="attestation">
                        <option value="direct" selected>Direct</option>
                    </select>
                    <select name="residentKey" data-webauthn--registration-target="residentKey">
                        <option value="required" selected>Required</option>
                    </select>
                    <select name="userVerification" data-webauthn--registration-target="userVerification">
                        <option value="required" selected>Required</option>
                    </select>
                    <select name="authenticatorAttachment" data-webauthn--registration-target="authenticatorAttachment">
                        <option value="platform" selected>Platform</option>
                    </select>
                    <button type="submit">Register</button>
                </form>
            `);

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test', rp: {}, user: {} }),
            });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({ id: 'cred' });

            const form = getByTestId(container, 'full-params-form');
            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(fetchMock).toHaveBeenCalledWith(
                    '/register/options',
                    expect.objectContaining({
                        method: 'POST',
                        body: JSON.stringify({
                            username: 'testuser',
                            attestation: 'direct',
                            residentKey: 'required',
                            userVerification: 'required',
                            authenticatorAttachment: 'platform',
                        }),
                    })
                );
            });
        });
    });

    describe('Error handling', () => {
        it('dispatches unsupported event when browser does not support WebAuthn', async () => {
            SimpleWebAuthnBrowser.browserSupportsWebAuthn.mockReturnValue(false);

            const form = getByTestId(container, 'registration-form');
            let unsupportedEvent = false;

            form.addEventListener('webauthn:unsupported', () => {
                unsupportedEvent = true;
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(unsupportedEvent).toBe(true);
            });
        });

        it('handles options fetch error', async () => {
            const form = getByTestId(container, 'registration-form');
            let errorEvent = null;

            form.addEventListener('webauthn:registration:options:error', (e) => {
                errorEvent = e.detail;
            });

            fetchMock.mockResolvedValueOnce({
                ok: false,
                status: 400,
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(errorEvent).toBeTruthy();
                expect(SimpleWebAuthnBrowser.startRegistration).not.toHaveBeenCalled();
            });
        });

        it('handles network error during options fetch', async () => {
            const form = getByTestId(container, 'registration-form');
            let errorEvent = null;

            form.addEventListener('webauthn:registration:options:error', (e) => {
                errorEvent = e.detail;
            });

            fetchMock.mockRejectedValueOnce(new Error('Network error'));

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(errorEvent).toBeTruthy();
                expect(errorEvent.error.message).toBe('Network error');
            });
        });

        it('handles WebAuthn registration error', async () => {
            const form = getByTestId(container, 'registration-form');
            let errorEvent = null;

            form.addEventListener('webauthn:registration:error', (e) => {
                errorEvent = e.detail;
            });

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test', rp: {}, user: {} }),
            });

            SimpleWebAuthnBrowser.startRegistration.mockRejectedValue(new Error('User cancelled'));

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(errorEvent).toBeTruthy();
                expect(errorEvent.error.message).toBe('User cancelled');
            });
        });

        it('handles authenticator error (NotAllowedError)', async () => {
            const form = getByTestId(container, 'registration-form');
            let errorEvent = null;

            form.addEventListener('webauthn:registration:error', (e) => {
                errorEvent = e.detail;
            });

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test', rp: {}, user: {} }),
            });

            const notAllowedError = new Error('The operation either timed out or was not allowed');
            notAllowedError.name = 'NotAllowedError';
            SimpleWebAuthnBrowser.startRegistration.mockRejectedValue(notAllowedError);

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(errorEvent).toBeTruthy();
                expect(errorEvent.error.name).toBe('NotAllowedError');
            });
        });

        it('handles verification error', async () => {
            const form = getByTestId(container, 'registration-form');
            let verifyErrorEvent = null;

            form.addEventListener('webauthn:registration:verify:error', (e) => {
                verifyErrorEvent = e.detail;
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test', rp: {}, user: {} }),
                })
                .mockResolvedValueOnce({
                    ok: false,
                    status: 400,
                });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({ id: 'cred' });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(verifyErrorEvent).toBeTruthy();
            });
        });

        it('handles duplicate credential error', async () => {
            const form = getByTestId(container, 'registration-form');
            let verifyErrorEvent = null;

            form.addEventListener('webauthn:registration:verify:error', (e) => {
                verifyErrorEvent = e.detail;
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test', rp: {}, user: {} }),
                })
                .mockResolvedValueOnce({
                    ok: false,
                    status: 409,
                });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({ id: 'cred' });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(verifyErrorEvent).toBeTruthy();
                expect(verifyErrorEvent.response.status).toBe(409);
            });
        });

        it('includes code and name for WebAuthnError', async () => {
            const form = getByTestId(container, 'registration-form');
            let errorEvent = null;

            form.addEventListener('webauthn:registration:error', (e) => {
                errorEvent = e.detail;
            });

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test', rp: {}, user: {} }),
            });

            const webAuthnError = new Error('Authenticator not responding');
            webAuthnError.name = 'NotReadableError';
            webAuthnError.code = 'ERROR_AUTHENTICATOR_NO_RESPONSE';
            Object.setPrototypeOf(webAuthnError, SimpleWebAuthnBrowser.WebAuthnError.prototype);

            SimpleWebAuthnBrowser.startRegistration.mockRejectedValue(webAuthnError);

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(errorEvent).toBeTruthy();
                expect(errorEvent.code).toBe('ERROR_AUTHENTICATOR_NO_RESPONSE');
                expect(errorEvent.name).toBe('NotReadableError');
            });
        });
    });

    describe('Form validation', () => {
        it('does not submit when form is invalid', async () => {
            container = mountDOM(`
                <form
                    data-testid="invalid-form"
                    data-controller="webauthn--registration"
                    data-action="submit->webauthn--registration#register"
                    data-webauthn--registration-options-url-value="/register/options"
                >
                    <input type="text" name="username" required data-webauthn--registration-target="username">
                    <button type="submit">Register</button>
                </form>
            `);

            const form = getByTestId(container, 'invalid-form');
            const usernameInput = form.querySelector('input[name="username"]');
            usernameInput.value = ''; // Empty value

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(fetchMock).not.toHaveBeenCalled();
            });
        });

        it('filters out empty optional parameters', async () => {
            container = mountDOM(`
                <form
                    data-testid="empty-params-form"
                    data-controller="webauthn--registration"
                    data-action="submit->webauthn--registration#register"
                    data-webauthn--registration-options-url-value="/register/options"
                >
                    <input type="text" name="username" value="testuser" data-webauthn--registration-target="username">
                    <select name="attestation" data-webauthn--registration-target="attestation">
                        <option value="">None selected</option>
                    </select>
                    <button type="submit">Register</button>
                </form>
            `);

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test', rp: {}, user: {} }),
            });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({ id: 'cred' });

            const form = getByTestId(container, 'empty-params-form');
            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                const callArgs = fetchMock.mock.calls[0][1];
                const body = JSON.parse(callArgs.body);
                expect(body).toEqual({ username: 'testuser' });
                expect(body.attestation).toBeUndefined();
            });
        });
    });

    describe('Events', () => {
        it('dispatches all success events in correct order', async () => {
            const form = getByTestId(container, 'registration-form');
            const events = [];

            form.addEventListener('webauthn:registration:options:request', () => events.push('options:request'));
            form.addEventListener('webauthn:registration:options:success', () => events.push('options:success'));
            form.addEventListener('webauthn:registration:credential', () => events.push('credential'));
            form.addEventListener('webauthn:registration:verify:request', () => events.push('verify:request'));
            form.addEventListener('webauthn:registration:verify:success', () => events.push('verify:success'));

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test', rp: {}, user: {} }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ verified: true }),
                });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({ id: 'cred' });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(events).toEqual([
                    'options:request',
                    'options:success',
                    'credential',
                    'verify:request',
                    'verify:success',
                ]);
            });
        });

        it('provides detailed error information in events', async () => {
            const form = getByTestId(container, 'registration-form');
            let errorDetail = null;

            form.addEventListener('webauthn:registration:error', (e) => {
                errorDetail = e.detail;
            });

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test', rp: {}, user: {} }),
            });

            const detailedError = new Error('Authenticator not responding');
            detailedError.name = 'NotReadableError';
            SimpleWebAuthnBrowser.startRegistration.mockRejectedValue(detailedError);

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(errorDetail).toBeTruthy();
                expect(errorDetail.error).toBeTruthy();
                expect(errorDetail.error.name).toBe('NotReadableError');
                expect(errorDetail.error.message).toBe('Authenticator not responding');
            });
        });
    });

    describe('PRF extension', () => {
        // 32 bytes of 0x41 ('A') round-tripped through the same helper the controller uses,
        // so the assertions stay in sync if SimpleWebAuthn ever changes its base64url output.
        const PRF_SALT_BYTES = new Uint8Array(32).fill(0x41).buffer;
        const PRF_SALT_B64 = SimpleWebAuthnBrowser.bufferToBase64URLString(PRF_SALT_BYTES);

        it('decodes base64url PRF inputs to ArrayBuffer before calling startRegistration', async () => {
            const form = getByTestId(container, 'registration-form');

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        challenge: 'test',
                        rp: {},
                        user: {},
                        extensions: { prf: { eval: { first: PRF_SALT_B64 } } },
                    }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({ id: 'cred' });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(SimpleWebAuthnBrowser.startRegistration).toHaveBeenCalled();
            });

            const call = SimpleWebAuthnBrowser.startRegistration.mock.calls[0][0];
            const first = call.optionsJSON.extensions.prf.eval.first;
            expect(first).toBeInstanceOf(ArrayBuffer);
            expect(first.byteLength).toBe(32);
            expect(new Uint8Array(first).every((b) => b === 0x41)).toBe(true);
        });

        it('encodes PRF results from ArrayBuffer back to base64url on the returned credential', async () => {
            const form = getByTestId(container, 'registration-form');
            const prfBytes = PRF_SALT_BYTES;

            const credentialEvents = [];
            form.addEventListener('webauthn:registration:credential', (e) => {
                credentialEvents.push(e.detail.credential);
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        challenge: 'test',
                        rp: {},
                        user: {},
                        extensions: { prf: { eval: { first: PRF_SALT_B64 } } },
                    }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({
                id: 'cred',
                clientExtensionResults: {
                    prf: { enabled: true, results: { first: prfBytes } },
                },
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(credentialEvents).toHaveLength(1);
            });
            expect(credentialEvents[0].clientExtensionResults.prf.enabled).toBe(true);
            expect(credentialEvents[0].clientExtensionResults.prf.results.first).toBe(PRF_SALT_B64);
        });

        it('decodes per-credential PRF inputs (evalByCredential)', async () => {
            const form = getByTestId(container, 'registration-form');

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        challenge: 'test',
                        rp: {},
                        user: {},
                        extensions: {
                            prf: {
                                evalByCredential: {
                                    'cred-1': { first: PRF_SALT_B64, second: PRF_SALT_B64 },
                                },
                            },
                        },
                    }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({ id: 'cred' });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(SimpleWebAuthnBrowser.startRegistration).toHaveBeenCalled();
            });
            const inputs =
                SimpleWebAuthnBrowser.startRegistration.mock.calls[0][0].optionsJSON.extensions.prf.evalByCredential[
                    'cred-1'
                ];
            expect(inputs.first).toBeInstanceOf(ArrayBuffer);
            expect(inputs.second).toBeInstanceOf(ArrayBuffer);
        });

        it('passes through credentials that do not use PRF', async () => {
            const form = getByTestId(container, 'registration-form');

            const credentialEvents = [];
            form.addEventListener('webauthn:registration:credential', (e) => {
                credentialEvents.push(e.detail.credential);
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test', rp: {}, user: {} }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({
                id: 'cred',
                clientExtensionResults: {},
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(credentialEvents).toHaveLength(1);
            });
            expect(credentialEvents[0].clientExtensionResults).toEqual({});
        });
    });

    describe('credBlob extension (CTAP 2.1 §12.2)', () => {
        it('decodes the credBlob input from base64url to ArrayBuffer before calling startRegistration', async () => {
            const form = getByTestId(container, 'registration-form');
            // base64url("hi!") = "aGkh"
            const blobB64 = 'aGkh';

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        challenge: 'test',
                        rp: {},
                        user: {},
                        extensions: { credBlob: blobB64 },
                    }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startRegistration.mockResolvedValue({ id: 'cred' });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(SimpleWebAuthnBrowser.startRegistration).toHaveBeenCalled();
            });
            const credBlob = SimpleWebAuthnBrowser.startRegistration.mock.calls[0][0].optionsJSON.extensions.credBlob;
            expect(credBlob).toBeInstanceOf(ArrayBuffer);
        });
    });

    describe('native L3 JSON helpers (parseCreationOptionsFromJSON / toJSON)', () => {
        // jsdom does not ship the L3 helpers; the AuthenticationController test
        // suite already exercises the SimpleWebAuthn fallback path. Here we
        // explicitly install the natives and check that the controller prefers
        // them when available, bypassing SimpleWebAuthn entirely.

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

        it('uses parseCreationOptionsFromJSON + navigator.credentials.create() when available', async () => {
            const form = getByTestId(container, 'registration-form');

            const parseSpy = jest.fn((json) => ({ __parsed: json }));
            Object.defineProperty(globalThis, 'PublicKeyCredential', {
                value: {
                    parseCreationOptionsFromJSON: parseSpy,
                    parseRequestOptionsFromJSON: jest.fn(),
                },
                configurable: true,
            });
            const credentialJson = {
                id: 'native-cred',
                type: 'public-key',
                rawId: 'native-cred',
                response: { clientDataJSON: 'd', attestationObject: 'a' },
                clientExtensionResults: {},
            };
            const createMock = jest.fn().mockResolvedValue({ toJSON: () => credentialJson });
            Object.defineProperty(globalThis, 'navigator', {
                value: { credentials: { create: createMock } },
                configurable: true,
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test', rp: {}, user: {} }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            const credentialEvents = [];
            form.addEventListener('webauthn:registration:credential', (e) => {
                credentialEvents.push(e.detail.credential);
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(createMock).toHaveBeenCalledTimes(1);
            });
            expect(parseSpy).toHaveBeenCalledTimes(1);
            expect(SimpleWebAuthnBrowser.startRegistration).not.toHaveBeenCalled();
            const callArg = createMock.mock.calls[0][0];
            expect(callArg.publicKey).toEqual({ __parsed: { challenge: 'test', rp: {}, user: {} } });
            expect(callArg.signal).toBeInstanceOf(AbortSignal);
            expect(credentialEvents[0]).toEqual(credentialJson);
        });

        it('forwards mediation: "conditional" on the native path when autoRegister is enabled', async () => {
            container = mountDOM(`
                <form
                    data-testid="auto-register-form"
                    data-controller="webauthn--registration"
                    data-action="submit->webauthn--registration#register"
                    data-webauthn--registration-options-url-value="/register/options"
                    data-webauthn--registration-auto-register-value="true"
                >
                </form>
            `);
            const form = getByTestId(container, 'auto-register-form');

            Object.defineProperty(globalThis, 'PublicKeyCredential', {
                value: {
                    parseCreationOptionsFromJSON: (json) => json,
                    parseRequestOptionsFromJSON: jest.fn(),
                },
                configurable: true,
            });
            const createMock = jest.fn().mockResolvedValue({ toJSON: () => ({ id: 'cred' }) });
            Object.defineProperty(globalThis, 'navigator', {
                value: { credentials: { create: createMock } },
                configurable: true,
            });

            fetchMock
                .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'x' }) })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(createMock).toHaveBeenCalledTimes(1);
            });
            expect(createMock.mock.calls[0][0].mediation).toBe('conditional');
        });
    });
});
