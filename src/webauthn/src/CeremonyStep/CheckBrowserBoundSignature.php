<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use function array_key_exists;
use function is_array;
use function is_string;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\SecurePaymentConfirmation\BrowserBoundSignatureVerifier;

/**
 * Cryptographically verifies the SPC `browserBoundSignature` returned in
 * the assertion's extension output. The browser-bound public key is read
 * from `clientDataJSON.payment.browserBoundPublicKey` (Chrome ships it
 * inline on every assertion so the relying party does not need to have
 * stashed it from registration). When the public key is absent — e.g. on
 * a non-Chromium user agent — verification is silently skipped and the
 * structural check performed by `PaymentExtensionOutputChecker` is the
 * only guarantee.
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
        if (! $authenticatorResponse instanceof AuthenticatorAssertionResponse) {
            return; // browserBoundSignature only ships in assertions.
        }
        if (! $publicKeyCredentialOptions instanceof PublicKeyCredentialRequestOptions) {
            return;
        }
        if (! $publicKeyCredentialOptions->extensions->has('payment')) {
            return; // Not an SPC ceremony.
        }

        $extensionsClientOutputs = $authenticatorResponse->authenticatorData->extensions;
        if ($extensionsClientOutputs === null || ! $extensionsClientOutputs->has('payment')) {
            return; // PaymentExtensionOutputChecker would already have raised.
        }
        $output = $extensionsClientOutputs->get('payment')
            ->value;
        if (! is_array($output)) {
            return;
        }
        $signature = $output['browserBoundSignature']['signature'] ?? null;
        if (! is_string($signature) || $signature === '') {
            return; // PaymentExtensionOutputChecker would already have raised.
        }

        $clientData = $authenticatorResponse->clientDataJSON;
        if (! $clientData->has('payment')) {
            return;
        }
        /** @var array<string, mixed> $payment */
        $payment = $clientData->get('payment');
        if (! array_key_exists('browserBoundPublicKey', $payment)
            || ! is_string($payment['browserBoundPublicKey'])
        ) {
            return; // No public key shipped — cannot verify.
        }

        $this->verifier->verify(
            clientDataJSON: $clientData->rawData,
            coseEncodedPublicKey: Base64UrlSafe::decodeNoPadding($payment['browserBoundPublicKey']),
            signature: Base64UrlSafe::decodeNoPadding($signature),
        );
    }
}
