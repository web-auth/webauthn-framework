'use strict';

import { Application } from '@hotwired/stimulus';
import { getByTestId, waitFor } from '@testing-library/dom';
import { clearDOM, mountDOM } from '@symfony/stimulus-testing';
import * as SimpleWebAuthnBrowser from '@simplewebauthn/browser';
import AuthenticationController from '../src/authentication-controller';

// Mock @simplewebauthn/browser but keep base64 helpers + WebAuthnError real so PRF
// processing in BaseController and `instanceof WebAuthnError` checks behave normally.
jest.mock('@simplewebauthn/browser', () => {
    const actual = jest.requireActual('@simplewebauthn/browser');
    return {
        ...actual,
        browserSupportsWebAuthn: jest.fn(),
        browserSupportsWebAuthnAutofill: jest.fn(),
        platformAuthenticatorIsAvailable: jest.fn(),
        startAuthentication: jest.fn(),
        WebAuthnAbortService: {
            cancelCeremony: jest.fn(),
            createNewAbortSignal: jest.fn(() => new AbortController().signal),
        },
    };
});

const startStimulus = () => {
    const application = Application.start();
    application.register('webauthn--authentication', AuthenticationController);
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
        form.addEventListener('webauthn:authentication:connect', resolve, { once: true });
    });
};

describe('AuthenticationController', () => {
    let container;
    let fetchMock;
    let application;

    beforeEach(() => {
        container = mountDOM(`
            <html lang="en">
                <head>
                    <title>WebAuthn Authentication Test</title>
                </head>
                <body>
                    <form
                        data-testid="authentication-form"
                        data-controller="webauthn--authentication"
                        data-action="submit->webauthn--authentication#authenticate"
                        data-webauthn--authentication-options-url-value="/auth/options"
                        data-webauthn--authentication-result-url-value="/auth/verify"
                    >
                        <input type="text" name="username" value="testuser" data-webauthn--authentication-target="username">
                        <input type="hidden" data-webauthn--authentication-target="result">
                        <button type="submit">Sign In</button>
                    </form>
                </body>
            </html>
        `);

        // Mock fetch globally
        fetchMock = jest.fn();
        globalThis.fetch = fetchMock;

        // Default mocks
        SimpleWebAuthnBrowser.browserSupportsWebAuthn.mockReturnValue(true);
        SimpleWebAuthnBrowser.browserSupportsWebAuthnAutofill.mockResolvedValue(false);
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
            const form = getByTestId(container, 'authentication-form');

            form.addEventListener('webauthn:authentication:connect', () => {
                eventDispatched = true;
            });

            application = startStimulus();

            await waitFor(() => expect(eventDispatched).toBe(true));
        });

        it('has correct target elements', async () => {
            application = startStimulus();
            const form = getByTestId(container, 'authentication-form');

            await waitFor(() => {
                const usernameInput = form.querySelector('[data-webauthn--authentication-target="username"]');
                const resultInput = form.querySelector('[data-webauthn--authentication-target="result"]');

                expect(usernameInput).toBeTruthy();
                expect(resultInput).toBeTruthy();
            });
        });
    });

    describe('Browser autofill', () => {
        it('does not start autofill when disabled', async () => {
            SimpleWebAuthnBrowser.browserSupportsWebAuthnAutofill.mockResolvedValue(true);

            application = startStimulus();

            await waitFor(() => {
                expect(SimpleWebAuthnBrowser.startAuthentication).not.toHaveBeenCalled();
            });
        });

        it('starts conditional UI when enabled and supported', async () => {
            container = mountDOM(`
                <form
                    data-testid="autofill-form"
                    data-controller="webauthn--authentication"
                    data-action="submit->webauthn--authentication#authenticate"
                    data-webauthn--authentication-conditional-ui-value="true"
                    data-webauthn--authentication-options-url-value="/auth/options"
                    data-webauthn--authentication-result-url-value="/auth/verify"
                >
                </form>
            `);

            SimpleWebAuthnBrowser.browserSupportsWebAuthnAutofill.mockResolvedValue(true);
            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test-challenge' }),
            });
            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({
                id: 'credential-id',
                rawId: 'credential-raw-id',
                response: { clientDataJSON: 'data' },
                type: 'public-key',
            });

            application = startStimulus();

            await waitFor(() => {
                expect(SimpleWebAuthnBrowser.startAuthentication).toHaveBeenCalledWith({
                    optionsJSON: { challenge: 'test-challenge' },
                    useBrowserAutofill: true,
                    verifyBrowserAutofillInput: true,
                });
            });
        });
    });

    describe('Successful authentication', () => {
        it('authenticates successfully with API verification', async () => {
            const form = getByTestId(container, 'authentication-form');
            const mockOptions = { challenge: 'test-challenge', rpId: 'example.com' };
            const mockCredential = {
                id: 'credential-id',
                rawId: 'credential-raw-id',
                response: { clientDataJSON: 'data', authenticatorData: 'auth-data', signature: 'sig' },
                type: 'public-key',
            };
            const mockVerification = { verified: true };

            let credentialEvent = null;
            form.addEventListener('webauthn:authentication:credential', (e) => {
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

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue(mockCredential);

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

        it('authenticates successfully with form submission', async () => {
            container = mountDOM(`
                <form
                    data-testid="form-submit"
                    data-controller="webauthn--authentication"
                    data-action="submit->webauthn--authentication#authenticate"
                    data-webauthn--authentication-options-url-value="/auth/options"
                    data-webauthn--authentication-submit-via-form-value="true"
                >
                    <input type="text" name="username" value="testuser">
                    <input type="hidden" data-webauthn--authentication-target="result">
                    <button type="submit">Sign In</button>
                </form>
            `);

            const form = getByTestId(container, 'form-submit');
            const mockCredential = { id: 'credential-id', type: 'public-key' };

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test' }),
            });

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue(mockCredential);

            const submitSpy = jest.spyOn(form, 'submit').mockImplementation(() => {});

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                const resultInput = form.querySelector('[data-webauthn--authentication-target="result"]');
                expect(resultInput.value).toBe(JSON.stringify(mockCredential));
                expect(submitSpy).toHaveBeenCalled();
            });
        });

        it('redirects on successful authentication when configured', async () => {
            container = mountDOM(`
                <form
                    data-testid="redirect-form"
                    data-controller="webauthn--authentication"
                    data-action="submit->webauthn--authentication#authenticate"
                    data-webauthn--authentication-options-url-value="/auth/options"
                    data-webauthn--authentication-result-url-value="/auth/verify"
                    data-webauthn--authentication-success-redirect-uri-value="/dashboard"
                >
                    <input type="text" name="username" value="testuser">
                    <button type="submit">Sign In</button>
                </form>
            `);

            // jsdom marks window.location as non-configurable. The
            // controller exposes _redirect() so tests can spy on it on the
            // prototype without fighting jsdom.
            const redirectSpy = jest
                .spyOn(AuthenticationController.prototype, '_redirect')
                .mockImplementation(() => {});

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test' }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ verified: true }),
                });

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({ id: 'cred' });

            const form = getByTestId(container, 'redirect-form');
            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            try {
                await waitFor(() => {
                    expect(redirectSpy).toHaveBeenCalledWith('/dashboard');
                });
            } finally {
                redirectSpy.mockRestore();
            }
        });
    });

    describe('Error handling', () => {
        it('dispatches unsupported event when browser does not support WebAuthn', async () => {
            SimpleWebAuthnBrowser.browserSupportsWebAuthn.mockReturnValue(false);

            const form = getByTestId(container, 'authentication-form');
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
            const form = getByTestId(container, 'authentication-form');
            let errorEvent = null;

            form.addEventListener('webauthn:authentication:options:error', (e) => {
                errorEvent = e.detail;
            });

            fetchMock.mockResolvedValueOnce({
                ok: false,
                status: 500,
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(errorEvent).toBeTruthy();
                expect(SimpleWebAuthnBrowser.startAuthentication).not.toHaveBeenCalled();
            });
        });

        it('handles network error during options fetch', async () => {
            const form = getByTestId(container, 'authentication-form');
            let errorEvent = null;

            form.addEventListener('webauthn:authentication:options:error', (e) => {
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

        it('handles WebAuthn authentication error', async () => {
            const form = getByTestId(container, 'authentication-form');
            let errorEvent = null;

            form.addEventListener('webauthn:authentication:error', (e) => {
                errorEvent = e.detail;
            });

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test' }),
            });

            SimpleWebAuthnBrowser.startAuthentication.mockRejectedValue(new Error('User cancelled'));

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(errorEvent).toBeTruthy();
                expect(errorEvent.error.message).toBe('User cancelled');
            });
        });

        it('handles verification error', async () => {
            const form = getByTestId(container, 'authentication-form');
            let verifyErrorEvent = null;

            form.addEventListener('webauthn:authentication:verify:error', (e) => {
                verifyErrorEvent = e.detail;
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test' }),
                })
                .mockResolvedValueOnce({
                    ok: false,
                    status: 401,
                });

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({ id: 'cred' });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(verifyErrorEvent).toBeTruthy();
            });
        });

        it('includes code and name for WebAuthnError', async () => {
            const form = getByTestId(container, 'authentication-form');
            let errorEvent = null;

            form.addEventListener('webauthn:authentication:error', (e) => {
                errorEvent = e.detail;
            });

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test' }),
            });

            const webAuthnError = new Error('User cancelled');
            webAuthnError.name = 'NotAllowedError';
            webAuthnError.code = 'ERROR_CEREMONY_ABORTED';
            Object.setPrototypeOf(webAuthnError, SimpleWebAuthnBrowser.WebAuthnError.prototype);

            SimpleWebAuthnBrowser.startAuthentication.mockRejectedValue(webAuthnError);

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            submitForm(form);

            await waitFor(() => {
                expect(errorEvent).toBeTruthy();
                expect(errorEvent.code).toBe('ERROR_CEREMONY_ABORTED');
                expect(errorEvent.name).toBe('NotAllowedError');
            });
        });
    });

    describe('Form validation', () => {
        it('does not submit when form is invalid', async () => {
            container = mountDOM(`
                <form
                    data-testid="invalid-form"
                    data-controller="webauthn--authentication"
                    data-action="submit->webauthn--authentication#authenticate"
                    data-webauthn--authentication-options-url-value="/auth/options"
                >
                    <input type="text" name="username" required data-webauthn--authentication-target="username">
                    <button type="submit">Sign In</button>
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
    });

    describe('Events', () => {
        it('dispatches all success events in correct order', async () => {
            const form = getByTestId(container, 'authentication-form');
            const events = [];

            form.addEventListener('webauthn:authentication:options:request', () => events.push('options:request'));
            form.addEventListener('webauthn:authentication:options:success', () => events.push('options:success'));
            form.addEventListener('webauthn:authentication:credential', () => events.push('credential'));
            form.addEventListener('webauthn:authentication:verify:request', () => events.push('verify:request'));
            form.addEventListener('webauthn:authentication:verify:success', () => events.push('verify:success'));

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test' }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ verified: true }),
                });

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({ id: 'cred' });

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
    });

    describe('PRF extension', () => {
        const PRF_SALT_BYTES = new Uint8Array(32).fill(0x41).buffer;
        const PRF_SALT_B64 = SimpleWebAuthnBrowser.bufferToBase64URLString(PRF_SALT_BYTES);

        it('decodes evalByCredential salts to ArrayBuffer before calling startAuthentication', async () => {
            const form = getByTestId(container, 'authentication-form');

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        challenge: 'test',
                        extensions: {
                            prf: {
                                evalByCredential: {
                                    'credential-id-base64url': { first: PRF_SALT_B64 },
                                },
                            },
                        },
                    }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({ id: 'cred' });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(SimpleWebAuthnBrowser.startAuthentication).toHaveBeenCalled();
            });

            const passed =
                SimpleWebAuthnBrowser.startAuthentication.mock.calls[0][0].optionsJSON.extensions.prf.evalByCredential[
                    'credential-id-base64url'
                ];
            expect(passed.first).toBeInstanceOf(ArrayBuffer);
            expect(passed.first.byteLength).toBe(32);
        });

        it('exposes PRF results as base64url on the dispatched credential event', async () => {
            const form = getByTestId(container, 'authentication-form');

            const credentialEvents = [];
            form.addEventListener('webauthn:authentication:credential', (e) => {
                credentialEvents.push(e.detail.credential);
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        challenge: 'test',
                        extensions: { prf: { eval: { first: PRF_SALT_B64 } } },
                    }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({
                id: 'cred',
                clientExtensionResults: {
                    prf: { results: { first: PRF_SALT_BYTES } },
                },
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(credentialEvents).toHaveLength(1);
            });
            expect(credentialEvents[0].clientExtensionResults.prf.results.first).toBe(PRF_SALT_B64);
        });

        it('passes through credentials that do not use PRF', async () => {
            const form = getByTestId(container, 'authentication-form');

            const credentialEvents = [];
            form.addEventListener('webauthn:authentication:credential', (e) => {
                credentialEvents.push(e.detail.credential);
            });

            fetchMock
                .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test' }) })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({
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

    describe('uiMode (Credential Management ED §2.3.3)', () => {
        // Per spec, when uiMode === "immediate" the user agent must return a
        // credential immediately available locally or fail with NotAllowedError.
        // SimpleWebAuthn 13.x has no native support for this option, so the
        // controller must bypass startAuthentication() and call
        // navigator.credentials.get() directly.

        let originalNavigator;

        beforeEach(() => {
            originalNavigator = globalThis.navigator;
        });

        afterEach(() => {
            if (originalNavigator) {
                Object.defineProperty(globalThis, 'navigator', {
                    value: originalNavigator,
                    configurable: true,
                });
            }
        });

        it('forwards uiMode "immediate" to navigator.credentials.get() and bypasses SimpleWebAuthn', async () => {
            const form = getByTestId(container, 'authentication-form');

            // base64url("hello") => "aGVsbG8"
            const challengeB64 = 'aGVsbG8';
            // base64url("cred-id") => "Y3JlZC1pZA"
            const credentialIdB64 = 'Y3JlZC1pZA';

            const credentialJson = {
                id: credentialIdB64,
                rawId: credentialIdB64,
                response: { clientDataJSON: 'data', authenticatorData: 'auth', signature: 'sig' },
                type: 'public-key',
            };
            const credentialsGetMock = jest.fn().mockResolvedValue({
                toJSON: () => credentialJson,
            });
            Object.defineProperty(globalThis, 'navigator', {
                value: { credentials: { get: credentialsGetMock } },
                configurable: true,
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        challenge: challengeB64,
                        rpId: 'example.com',
                        allowCredentials: [{ type: 'public-key', id: credentialIdB64 }],
                        uiMode: 'immediate',
                    }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            let credentialEvent = null;
            form.addEventListener('webauthn:authentication:credential', (e) => {
                credentialEvent = e.detail;
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(credentialsGetMock).toHaveBeenCalledTimes(1);
            });

            const callArg = credentialsGetMock.mock.calls[0][0];
            expect(callArg.uiMode).toBe('immediate');
            expect(callArg.publicKey.uiMode).toBeUndefined();
            expect(callArg.publicKey.challenge).toBeInstanceOf(ArrayBuffer);
            expect(callArg.publicKey.allowCredentials[0].id).toBeInstanceOf(ArrayBuffer);
            expect(callArg.signal).toBeInstanceOf(AbortSignal);

            expect(SimpleWebAuthnBrowser.startAuthentication).not.toHaveBeenCalled();
            expect(credentialEvent.credential).toEqual(credentialJson);
        });

        it('rejects an unknown uiMode value before reaching the browser', async () => {
            const form = getByTestId(container, 'authentication-form');

            fetchMock.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ challenge: 'test', uiMode: 'silent' }),
            });

            let errorDetail = null;
            form.addEventListener('webauthn:authentication:error', (e) => {
                errorDetail = e.detail;
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(errorDetail).not.toBeNull();
            });
            expect(errorDetail.error).toBeInstanceOf(TypeError);
            expect(errorDetail.error.message).toContain('Invalid uiMode "silent"');
            expect(SimpleWebAuthnBrowser.startAuthentication).not.toHaveBeenCalled();
        });

        it('falls back to startAuthentication when uiMode is absent', async () => {
            const form = getByTestId(container, 'authentication-form');

            fetchMock
                .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test' }) })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({ id: 'cred' });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(SimpleWebAuthnBrowser.startAuthentication).toHaveBeenCalledTimes(1);
            });
            const startCall = SimpleWebAuthnBrowser.startAuthentication.mock.calls[0][0];
            expect(startCall.optionsJSON).toEqual({ challenge: 'test' });
            expect(startCall.optionsJSON.uiMode).toBeUndefined();
        });
    });

    describe('credBlob extension (CTAP 2.1 §12.2)', () => {
        it('encodes the credBlob assertion output ArrayBuffer back to base64url before dispatch', async () => {
            const form = getByTestId(container, 'authentication-form');
            const blobBytes = new Uint8Array([0x68, 0x69, 0x21]).buffer; // base64url("hi!") = "aGkh"

            fetchMock
                .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test' }) })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({
                id: 'cred',
                clientExtensionResults: { credBlob: blobBytes },
            });

            const credentialEvents = [];
            form.addEventListener('webauthn:authentication:credential', (e) => {
                credentialEvents.push(e.detail.credential);
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(credentialEvents).toHaveLength(1);
            });
            expect(credentialEvents[0].clientExtensionResults.credBlob).toBe('aGkh');
        });
    });

    describe('getClientCapabilities (WebAuthn L3 §5.1.7)', () => {
        let originalPublicKeyCredential;

        beforeEach(() => {
            originalPublicKeyCredential = globalThis.PublicKeyCredential;
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
        });

        it('exposes the native capability map on the connect event when available', async () => {
            const form = getByTestId(container, 'authentication-form');
            const nativeCaps = {
                conditionalGet: true,
                conditionalCreate: false,
                relatedOrigins: true,
            };
            Object.defineProperty(globalThis, 'PublicKeyCredential', {
                value: { getClientCapabilities: jest.fn().mockResolvedValue(nativeCaps) },
                configurable: true,
            });

            let connectDetail = null;
            form.addEventListener('webauthn:authentication:connect', (e) => {
                connectDetail = e.detail;
            });
            application = startStimulus();

            await waitFor(() => expect(connectDetail).not.toBeNull());
            expect(connectDetail.capabilities).toEqual(nativeCaps);
        });

        it('falls back to a synthetic map when the native API is missing', async () => {
            // jsdom default state: no PublicKeyCredential, browserSupportsWebAuthnAutofill
            // is mocked at file scope to resolve false.
            delete globalThis.PublicKeyCredential;

            const form = getByTestId(container, 'authentication-form');
            let connectDetail = null;
            form.addEventListener('webauthn:authentication:connect', (e) => {
                connectDetail = e.detail;
            });
            application = startStimulus();

            await waitFor(() => expect(connectDetail).not.toBeNull());
            expect(connectDetail.capabilities).toEqual({ conditionalGet: false });
        });

        it('skips conditional UI when capabilities.conditionalGet is false even if requested', async () => {
            container = mountDOM(`
                <form
                    data-testid="capabilities-cond-form"
                    data-controller="webauthn--authentication"
                    data-action="submit->webauthn--authentication#authenticate"
                    data-webauthn--authentication-conditional-ui-value="true"
                    data-webauthn--authentication-options-url-value="/auth/options"
                    data-webauthn--authentication-result-url-value="/auth/verify"
                >
                </form>
            `);

            Object.defineProperty(globalThis, 'PublicKeyCredential', {
                value: {
                    getClientCapabilities: jest.fn().mockResolvedValue({ conditionalGet: false }),
                },
                configurable: true,
            });

            const form = getByTestId(container, 'capabilities-cond-form');
            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;

            // Give the post-connect conditional-UI branch a tick to no-op.
            await new Promise((r) => setTimeout(r, 0));

            expect(fetchMock).not.toHaveBeenCalled();
            expect(SimpleWebAuthnBrowser.startAuthentication).not.toHaveBeenCalled();
        });

        it('starts conditional UI when capabilities.conditionalGet is true', async () => {
            container = mountDOM(`
                <form
                    data-testid="capabilities-cond-form-on"
                    data-controller="webauthn--authentication"
                    data-action="submit->webauthn--authentication#authenticate"
                    data-webauthn--authentication-conditional-ui-value="true"
                    data-webauthn--authentication-options-url-value="/auth/options"
                    data-webauthn--authentication-result-url-value="/auth/verify"
                >
                </form>
            `);

            Object.defineProperty(globalThis, 'PublicKeyCredential', {
                value: {
                    getClientCapabilities: jest.fn().mockResolvedValue({ conditionalGet: true }),
                },
                configurable: true,
            });
            fetchMock.mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'c' }) });
            SimpleWebAuthnBrowser.startAuthentication.mockResolvedValue({ id: 'cred' });

            application = startStimulus();

            await waitFor(() => {
                expect(SimpleWebAuthnBrowser.startAuthentication).toHaveBeenCalled();
            });
        });
    });

    describe('native L3 JSON helpers (parseRequestOptionsFromJSON / toJSON)', () => {
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

        it('uses parseRequestOptionsFromJSON + navigator.credentials.get() when available', async () => {
            const form = getByTestId(container, 'authentication-form');

            const parseSpy = jest.fn((json) => ({ __parsed: json }));
            Object.defineProperty(globalThis, 'PublicKeyCredential', {
                value: {
                    parseCreationOptionsFromJSON: jest.fn(),
                    parseRequestOptionsFromJSON: parseSpy,
                },
                configurable: true,
            });
            const credentialJson = {
                id: 'native-cred',
                type: 'public-key',
                rawId: 'native-cred',
                response: { clientDataJSON: 'd', authenticatorData: 'a', signature: 's' },
                clientExtensionResults: {},
            };
            const getMock = jest.fn().mockResolvedValue({ toJSON: () => credentialJson });
            Object.defineProperty(globalThis, 'navigator', {
                value: { credentials: { get: getMock } },
                configurable: true,
            });

            fetchMock
                .mockResolvedValueOnce({ ok: true, json: async () => ({ challenge: 'test' }) })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            const credentialEvents = [];
            form.addEventListener('webauthn:authentication:credential', (e) => {
                credentialEvents.push(e.detail.credential);
            });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(getMock).toHaveBeenCalledTimes(1);
            });
            expect(parseSpy).toHaveBeenCalledTimes(1);
            expect(SimpleWebAuthnBrowser.startAuthentication).not.toHaveBeenCalled();
            const callArg = getMock.mock.calls[0][0];
            expect(callArg.publicKey).toEqual({ __parsed: { challenge: 'test' } });
            expect(callArg.signal).toBeInstanceOf(AbortSignal);
            expect(credentialEvents[0]).toEqual(credentialJson);
        });

        it('forwards uiMode "immediate" through navigator.credentials.get() on the native path', async () => {
            const form = getByTestId(container, 'authentication-form');

            Object.defineProperty(globalThis, 'PublicKeyCredential', {
                value: {
                    parseCreationOptionsFromJSON: jest.fn(),
                    parseRequestOptionsFromJSON: (json) => json,
                },
                configurable: true,
            });
            const getMock = jest.fn().mockResolvedValue({ toJSON: () => ({ id: 'cred' }) });
            Object.defineProperty(globalThis, 'navigator', {
                value: { credentials: { get: getMock } },
                configurable: true,
            });

            fetchMock
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ challenge: 'test', uiMode: 'immediate' }),
                })
                .mockResolvedValueOnce({ ok: true, json: async () => ({ verified: true }) });

            const connectionPromise = waitForConnection(form);
            application = startStimulus();
            await connectionPromise;
            submitForm(form);

            await waitFor(() => {
                expect(getMock).toHaveBeenCalledTimes(1);
            });
            const callArg = getMock.mock.calls[0][0];
            expect(callArg.uiMode).toBe('immediate');
            expect(callArg.publicKey.uiMode).toBeUndefined();
        });
    });
});
