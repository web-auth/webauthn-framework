'use strict';

import { Application } from '@hotwired/stimulus';
import { getByTestId, waitFor } from '@testing-library/dom';
import { clearDOM, mountDOM } from '@symfony/stimulus-testing';
import AuthenticationController from '../src/authentication-controller';

const startStimulus = () => {
    const application = Application.start();
    application.register('webauthn--authentication', AuthenticationController);
    return application;
};

describe('AuthenticationController', () => {
    let container;

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
                        data-webauthn--authentication-options-url-value="/auth/options"
                        data-webauthn--authentication-result-url-value="/auth/verify"
                    >
                        <input type="text" name="username" data-webauthn--authentication-target="username">
                        <input type="hidden" data-webauthn--authentication-target="result">
                        <button type="submit">Sign In</button>
                    </form>
                </body>
            </html>
        `);
    });

    afterEach(() => {
        clearDOM();
    });

    it('connects and dispatches event', async () => {
        let eventDispatched = false;
        const form = getByTestId(container, 'authentication-form');

        form.addEventListener('webauthn:authentication:connect', () => {
            eventDispatched = true;
        });

        startStimulus();

        await waitFor(() => expect(eventDispatched).toBe(true));
    });

    it('has correct target elements', async () => {
        startStimulus();
        const form = getByTestId(container, 'authentication-form');

        await waitFor(() => {
            const usernameInput = form.querySelector('[data-webauthn--authentication-target="username"]');
            const resultInput = form.querySelector('[data-webauthn--authentication-target="result"]');

            expect(usernameInput).toBeTruthy();
            expect(resultInput).toBeTruthy();
        });
    });
});
