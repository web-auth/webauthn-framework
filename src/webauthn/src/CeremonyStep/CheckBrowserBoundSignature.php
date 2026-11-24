<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use function is_array;
use function is_string;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\SecurePaymentConfirmation\BrowserBoundSignatureVerifier;
use Webauthn\Util\Base64;

/**
 * Verifies the browser-bound key outputs of a Secure Payment Confirmation ceremony, at registration and at
 * authentication, whenever the stored options carry the `payment` extension.
 *
 * W3C Secure Payment Confirmation returns them in two places. The browser-bound public key, a base64url COSE_Key,
 * is in `clientDataJSON.payment.browserBoundPublicKey`. The browser-bound signature, made with the matching private
 * key over the raw `clientDataJSON`, is a client extension result: `clientExtensionResults.payment
 * .browserBoundSignature.signature`. Neither is in the authenticator data.
 *
 * The user agent produces both or neither: it omits them when it cannot create or bind a browser-bound key, for
 * instance when it supports none of the requested algorithms. So:
 *   - neither present: the ceremony goes on with the passkey signature alone, as the specification allows;
 *   - both present: the signature must verify against the public key, or the ceremony fails;
 *   - only one of them, or a malformed value: the ceremony fails. The public key sits in the client data, which the
 *     authenticator signs at authentication, so a signature missing next to it means the client dropped it, typically
 *     because `clientExtensionResults` was not forwarded with the response.
 *
 * After a successful ceremony, a browser-bound public key found in the client data has proven possession of its
 * private key. Relying parties that bind payments to a device store it at registration and compare it on the next
 * authentications.
 *
 * @see https://w3c.github.io/secure-payment-confirmation/#sctn-payment-extension-registration
 */
final readonly class CheckBrowserBoundSignature implements CeremonyStep
{
    public function __construct(
        private BrowserBoundSignatureVerifier $verifier,
    ) {
    }

    public function process(
        CredentialRecord $credentialRecord,
        AuthenticatorAssertionResponse|AuthenticatorAttestationResponse $authenticatorResponse,
        PublicKeyCredentialRequestOptions|PublicKeyCredentialCreationOptions $publicKeyCredentialOptions,
        ?string $userHandle,
        string $host
    ): void {
        if (! $publicKeyCredentialOptions->extensions->has('payment')) {
            return;
        }

        $publicKey = self::browserBoundPublicKey($authenticatorResponse->clientDataJSON);
        $signature = self::browserBoundSignature($authenticatorResponse->clientExtensionResults);
        if ($publicKey === null && $signature === null) {
            return;
        }
        $publicKey !== null || throw AuthenticatorResponseVerificationException::create(
            'A browser-bound signature was returned, but the client data carries no browser-bound public key.'
        );
        $signature !== null || throw AuthenticatorResponseVerificationException::create(
            'The client data carries a browser-bound public key, but the browser-bound signature is missing from the client extension results. The client must send "clientExtensionResults" with the credential.'
        );

        $this->verifier->verify($authenticatorResponse->clientDataJSON->rawData, $publicKey, $signature);
    }

    private static function browserBoundPublicKey(CollectedClientData $clientData): null|string
    {
        if (! $clientData->has('payment')) {
            return null;
        }
        $payment = $clientData->get('payment');
        if (! is_array($payment) || ! isset($payment['browserBoundPublicKey'])) {
            return null;
        }

        return self::decode($payment['browserBoundPublicKey'], 'browser-bound public key');
    }

    private static function browserBoundSignature(null|AuthenticationExtensions $clientExtensionResults): null|string
    {
        if ($clientExtensionResults === null || ! $clientExtensionResults->has('payment')) {
            return null;
        }
        $payment = $clientExtensionResults->get('payment')
            ->value;
        is_array($payment) || throw AuthenticatorResponseVerificationException::create(
            'Invalid payment extension output: expected an object.'
        );
        if (! isset($payment['browserBoundSignature'])) {
            return null;
        }
        $browserBoundSignature = $payment['browserBoundSignature'];
        is_array($browserBoundSignature) || throw AuthenticatorResponseVerificationException::create(
            'Invalid payment extension output: "browserBoundSignature" must be an object.'
        );

        return self::decode($browserBoundSignature['signature'] ?? null, 'browser-bound signature');
    }

    private static function decode(mixed $value, string $name): string
    {
        is_string($value) && $value !== '' || throw AuthenticatorResponseVerificationException::create(
            'Invalid ' . $name . ': expected a non-empty base64url string.'
        );
        try {
            $decoded = Base64::decode($value);
        } catch (Throwable $e) {
            throw AuthenticatorResponseVerificationException::create(
                'Invalid ' . $name . ': expected a non-empty base64url string.',
                $e
            );
        }
        $decoded !== '' || throw AuthenticatorResponseVerificationException::create(
            'Invalid ' . $name . ': expected a non-empty base64url string.'
        );

        return $decoded;
    }
}
