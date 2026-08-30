'use strict';

import { bufferToBase64URLString } from '@simplewebauthn/browser';
import AuthenticationController from './authentication-controller.js';

/**
 * Stimulus controller for W3C Secure Payment Confirmation (SPC).
 *
 * Reuses the AuthenticationController ceremony machinery — `startAuthentication`
 * recognises the `payment` extension automatically and triggers the SPC user
 * confirmation UI, so no dedicated `startPayment()` API is required (per
 * SimpleWebAuthn server docs: "SPC responses are almost identical to WebAuthn
 * responses, save for a slightly different value in their `type` value within
 * `clientDataJSON`").
 *
 * The server returns `extensions.payment` with the transaction payload
 * (`isPayment`, `rpId`, `topOrigin`, `total`, `instrument`, `payeeName`,
 * `payeeOrigin`, optional `paymentEntitiesLogos`, optional
 * `browserBoundPubKeyCredParams`) — already JSON-serialisable, so no input
 * conversion is required. On the way back, `clientExtensionResults.payment`
 * carries `browserBoundSignature.signature` as an ArrayBuffer that we encode
 * to base64url for transport to the verifier.
 *
 * Usage:
 * <form data-controller="webauthn--payment"
 *       data-webauthn--payment-options-url-value="/payment/options"
 *       data-webauthn--payment-result-url-value="/payment/verify"
 *       data-action="submit->webauthn--payment#authenticate">
 *   <input type="hidden" data-webauthn--payment-target="result">
 *   <button type="submit">Confirm payment</button>
 * </form>
 */
export default class extends AuthenticationController {
    static values = {
        ...AuthenticationController.values,
        optionsUrl: { type: String, default: '/payment/options' },
        resultUrl: { type: String, default: '/payment/verify' },
    };

    /**
     * Hand the `payment` extension input to the user agent unchanged.
     * The browser displays its own SPC confirmation UI from these fields.
     * @param {Object} options - WebAuthn request options
     * @returns {Object} options
     */
    _processExtensionsInput(options) {
        return super._processExtensionsInput(options);
    }

    /**
     * Decode the SPC `browserBoundSignature.signature` ArrayBuffer to base64url
     * so the credential is JSON-serialisable for transport to the relying party.
     * @param {Object} credential - WebAuthn credential
     * @returns {Object} credential
     */
    _processExtensionsOutput(credential) {
        credential = super._processExtensionsOutput(credential);

        const payment = credential?.clientExtensionResults?.payment;
        if (payment?.browserBoundSignature?.signature instanceof ArrayBuffer) {
            payment.browserBoundSignature.signature = bufferToBase64URLString(payment.browserBoundSignature.signature);
        }

        return credential;
    }
}
