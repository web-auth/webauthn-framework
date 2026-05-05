'use strict';

/**
 * WebAuthn L3 §5.1.10 Signal API:fire-and-forget client-side dispatchers.
 *
 * The three exported functions are thin wrappers around the matching
 * `PublicKeyCredential.signalXxx()` static methods. Each one:
 *
 *  - feature-detects the method on the current user agent and silently
 *    no-ops when it is not present (Firefox, older Safari, etc.);
 *  - swallows the spec-defined `TypeError` (malformed base64url id) and
 *    `SecurityError` (RP-ID mismatch) without rejecting, since the spec
 *    itself is intentionally non-informative on success:a resolved
 *    promise only means the options object was well formed (W3C §5.1.10);
 *  - returns a `Promise<void>` for ergonomic chaining but never rejects.
 *
 * Per W3C §14.6.3:
 *  - `dispatchUnknownCredential` is safe to call from an unauthenticated
 *    page (the credential id is one the caller already presented);
 *  - `dispatchAllAcceptedCredentials` and `dispatchCurrentUserDetails`
 *    expose PII (full credential id list / user handle + display strings)
 *    and MUST only be called for an authenticated user.
 */

const DISPATCHERS = {
    unknownCredential: 'signalUnknownCredential',
    allAcceptedCredentials: 'signalAllAcceptedCredentials',
    currentUserDetails: 'signalCurrentUserDetails',
};

const dispatch = async (method, options) => {
    if (typeof PublicKeyCredential === 'undefined' || typeof PublicKeyCredential[method] !== 'function') {
        return;
    }
    try {
        await PublicKeyCredential[method](options);
    } catch (error) {
        if (error instanceof TypeError || error.name === 'SecurityError') {
            return;
        }
        throw error;
    }
};

/**
 * Notify the user agent that a credential id is no longer recognised by
 * the relying party.
 *
 * @param {{rpId: string, credentialId: string}} options
 * @returns {Promise<void>}
 */
export const dispatchUnknownCredential = (options) => dispatch('signalUnknownCredential', options);

/**
 * Notify the user agent of the complete list of credential ids currently
 * accepted by the relying party for `userId`. Credentials missing from
 * the list MAY be removed or hidden by the authenticator (potentially
 * irreversibly:see W3C §5.1.10.3).
 *
 * @param {{rpId: string, userId: string, allAcceptedCredentialIds: string[]}} options
 * @returns {Promise<void>}
 */
export const dispatchAllAcceptedCredentials = (options) => dispatch('signalAllAcceptedCredentials', options);

/**
 * Notify the user agent that the user's `name` and `displayName` have
 * changed, so the password manager can refresh the matching passkey label.
 *
 * @param {{rpId: string, userId: string, name: string, displayName: string}} options
 * @returns {Promise<void>}
 */
export const dispatchCurrentUserDetails = (options) => dispatch('signalCurrentUserDetails', options);

/**
 * Dispatch every entry of a `signals: [{type, options}]` envelope produced
 * by {@link \Webauthn\Bundle\Service\WebauthnSignalResponse} server-side.
 *
 * Unknown `type` values are skipped silently (forward-compatibility: a
 * future server may emit a type the current client does not understand).
 *
 * @param {{signals?: Array<{type: string, options: object}>}|null|undefined} envelope
 * @returns {Promise<void>}
 */
export const dispatchSignals = async (envelope) => {
    const signals = envelope?.signals;
    if (!Array.isArray(signals) || signals.length === 0) {
        return;
    }
    await Promise.all(
        signals.map(({ type, options } = {}) => {
            const method = DISPATCHERS[type];
            if (!method || !options) {
                return undefined;
            }
            return dispatch(method, options);
        })
    );
};
