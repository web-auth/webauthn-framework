'use strict';

import '@symfony/stimulus-testing/setup';

// Polyfill for jsdom's missing requestSubmit
if (typeof HTMLFormElement.prototype.requestSubmit === 'undefined') {
    HTMLFormElement.prototype.requestSubmit = function (submitter) {
        if (submitter) {
            submitter.click();
            return;
        }

        const submitEvent = new Event('submit', {
            bubbles: true,
            cancelable: true,
        });

        this.dispatchEvent(submitEvent);
    };
}
