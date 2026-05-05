'use strict';

import {
    dispatchAllAcceptedCredentials,
    dispatchCurrentUserDetails,
    dispatchSignals,
    dispatchUnknownCredential,
} from '../src/signals';

describe('signals.js, WebAuthn L3 §5.1.10 dispatchers', () => {
    beforeEach(() => {
        // Reset the global PublicKeyCredential surface for each test.
        globalThis.PublicKeyCredential = {
            signalUnknownCredential: jest.fn().mockResolvedValue(undefined),
            signalAllAcceptedCredentials: jest.fn().mockResolvedValue(undefined),
            signalCurrentUserDetails: jest.fn().mockResolvedValue(undefined),
        };
    });

    afterEach(() => {
        delete globalThis.PublicKeyCredential;
    });

    test('dispatchUnknownCredential forwards options to PublicKeyCredential.signalUnknownCredential', async () => {
        const options = { rpId: 'example.com', credentialId: 'aabbcc' };

        await dispatchUnknownCredential(options);

        expect(globalThis.PublicKeyCredential.signalUnknownCredential).toHaveBeenCalledWith(options);
        expect(globalThis.PublicKeyCredential.signalAllAcceptedCredentials).not.toHaveBeenCalled();
        expect(globalThis.PublicKeyCredential.signalCurrentUserDetails).not.toHaveBeenCalled();
    });

    test('dispatchAllAcceptedCredentials forwards options to the matching method', async () => {
        const options = { rpId: 'example.com', userId: 'aa', allAcceptedCredentialIds: ['bb', 'cc'] };

        await dispatchAllAcceptedCredentials(options);

        expect(globalThis.PublicKeyCredential.signalAllAcceptedCredentials).toHaveBeenCalledWith(options);
    });

    test('dispatchCurrentUserDetails forwards options to the matching method', async () => {
        const options = { rpId: 'example.com', userId: 'aa', name: 'alice', displayName: 'Alice' };

        await dispatchCurrentUserDetails(options);

        expect(globalThis.PublicKeyCredential.signalCurrentUserDetails).toHaveBeenCalledWith(options);
    });

    test('dispatchers silently no-op when the user agent does not implement the method', async () => {
        globalThis.PublicKeyCredential = {}; // no signal methods

        await expect(dispatchUnknownCredential({ rpId: 'x', credentialId: 'y' })).resolves.toBeUndefined();
        await expect(
            dispatchAllAcceptedCredentials({ rpId: 'x', userId: 'y', allAcceptedCredentialIds: [] })
        ).resolves.toBeUndefined();
        await expect(
            dispatchCurrentUserDetails({ rpId: 'x', userId: 'y', name: 'a', displayName: 'A' })
        ).resolves.toBeUndefined();
    });

    test('dispatchers silently no-op when PublicKeyCredential itself is missing', async () => {
        delete globalThis.PublicKeyCredential;

        await expect(dispatchUnknownCredential({ rpId: 'x', credentialId: 'y' })).resolves.toBeUndefined();
    });

    test('dispatchers swallow TypeError (malformed base64url) without rejecting', async () => {
        globalThis.PublicKeyCredential.signalUnknownCredential = jest
            .fn()
            .mockRejectedValueOnce(new TypeError('bad base64url'));

        await expect(dispatchUnknownCredential({ rpId: 'x', credentialId: '###' })).resolves.toBeUndefined();
    });

    test('dispatchers swallow SecurityError (RP-ID mismatch) without rejecting', async () => {
        const securityError = Object.assign(new Error('RP-ID does not match'), { name: 'SecurityError' });
        globalThis.PublicKeyCredential.signalAllAcceptedCredentials = jest
            .fn()
            .mockRejectedValueOnce(securityError);

        await expect(
            dispatchAllAcceptedCredentials({ rpId: 'wrong', userId: 'y', allAcceptedCredentialIds: [] })
        ).resolves.toBeUndefined();
    });

    test('dispatchers re-throw unrelated errors', async () => {
        globalThis.PublicKeyCredential.signalCurrentUserDetails = jest
            .fn()
            .mockRejectedValueOnce(new Error('something else'));

        await expect(
            dispatchCurrentUserDetails({ rpId: 'x', userId: 'y', name: 'a', displayName: 'A' })
        ).rejects.toThrow('something else');
    });

    describe('dispatchSignals envelope router', () => {
        test('routes each entry to the matching dispatcher', async () => {
            const envelope = {
                signals: [
                    {
                        type: 'allAcceptedCredentials',
                        options: { rpId: 'example.com', userId: 'aa', allAcceptedCredentialIds: ['bb'] },
                    },
                    {
                        type: 'currentUserDetails',
                        options: { rpId: 'example.com', userId: 'aa', name: 'alice', displayName: 'Alice' },
                    },
                ],
            };

            await dispatchSignals(envelope);

            expect(globalThis.PublicKeyCredential.signalAllAcceptedCredentials).toHaveBeenCalledWith(
                envelope.signals[0].options
            );
            expect(globalThis.PublicKeyCredential.signalCurrentUserDetails).toHaveBeenCalledWith(
                envelope.signals[1].options
            );
            expect(globalThis.PublicKeyCredential.signalUnknownCredential).not.toHaveBeenCalled();
        });

        test('silently skips entries with an unknown type (forward-compat)', async () => {
            await dispatchSignals({
                signals: [
                    { type: 'futureSignal', options: { rpId: 'x' } },
                    {
                        type: 'unknownCredential',
                        options: { rpId: 'example.com', credentialId: 'aabbcc' },
                    },
                ],
            });

            expect(globalThis.PublicKeyCredential.signalUnknownCredential).toHaveBeenCalledTimes(1);
        });

        test('does nothing on an envelope without a signals array', async () => {
            await expect(dispatchSignals(null)).resolves.toBeUndefined();
            await expect(dispatchSignals(undefined)).resolves.toBeUndefined();
            await expect(dispatchSignals({})).resolves.toBeUndefined();
            await expect(dispatchSignals({ signals: [] })).resolves.toBeUndefined();

            expect(globalThis.PublicKeyCredential.signalUnknownCredential).not.toHaveBeenCalled();
            expect(globalThis.PublicKeyCredential.signalAllAcceptedCredentials).not.toHaveBeenCalled();
            expect(globalThis.PublicKeyCredential.signalCurrentUserDetails).not.toHaveBeenCalled();
        });
    });
});
