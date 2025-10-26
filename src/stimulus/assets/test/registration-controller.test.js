'use strict';

import { Application } from '@hotwired/stimulus';
import { getByTestId, waitFor } from '@testing-library/dom';
import { clearDOM, mountDOM } from '@symfony/stimulus-testing';
import * as SimpleWebAuthnBrowser from '@simplewebauthn/browser';
import RegistrationController from '../src/registration-controller';

// Mock @simplewebauthn/browser
jest.mock('@simplewebauthn/browser');

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
        global.fetch = fetchMock;

        // Default mocks
        SimpleWebAuthnBrowser.browserSupportsWebAuthn.mockReturnValue(true);
    });

    afterEach(() => {
        if (application) {
            application.stop();
            application = null;
        }
        clearDOM();
        jest.clearAllMocks();
        delete global.fetch;
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
                    data-webauthn--registration-use-result-target-value="true"
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

            delete window.location;
            window.location = { replace: jest.fn() };

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

            await waitFor(() => {
                expect(window.location.replace).toHaveBeenCalledWith('/profile');
            });
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
});
