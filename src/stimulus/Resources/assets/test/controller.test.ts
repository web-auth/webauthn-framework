'use strict';

import { Application, Controller } from '@hotwired/stimulus';
import { getByTestId, waitFor } from '@testing-library/dom';
import { clearDOM, mountDOM } from '@symfony/stimulus-testing';
import WebauthnController from '../src/controller';

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
};

describe('WebauthnController', () => {
    let container;

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
        clearDOM();
    });

    it('pre-connect', async () => {
        expect(getByTestId(container, 'webauthn')).not.toHaveClass('connected');

        startStimulus();
        await waitFor(() => expect(getByTestId(container, 'webauthn')).toHaveClass('connected'));
    });
});
