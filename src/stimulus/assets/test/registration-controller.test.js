'use strict';

import { Application } from '@hotwired/stimulus';
import { getByTestId, waitFor } from '@testing-library/dom';
import { clearDOM, mountDOM } from '@symfony/stimulus-testing';
import RegistrationController from '../src/registration-controller';

const startStimulus = () => {
    const application = Application.start();
    application.register('webauthn--registration', RegistrationController);
    return application;
};

describe('RegistrationController', () => {
    let container;

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
                        data-webauthn--registration-options-url-value="/register/options"
                        data-webauthn--registration-result-url-value="/register/verify"
                    >
                        <input type="text" name="username" data-webauthn--registration-target="username">
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
    });

    afterEach(() => {
        clearDOM();
    });

    it('connects and dispatches event', async () => {
        let eventDispatched = false;
        const form = getByTestId(container, 'registration-form');

        form.addEventListener('webauthn:registration:connect', () => {
            eventDispatched = true;
        });

        startStimulus();

        await waitFor(() => expect(eventDispatched).toBe(true));
    });

    it('has correct target elements', async () => {
        startStimulus();
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
