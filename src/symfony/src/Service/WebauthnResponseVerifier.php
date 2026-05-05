<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Storage\OptionsStorage;

/**
 * Single, autowired entry point that produces a fluent
 * {@see WebauthnAttestationVerifier} or {@see WebauthnAssertionVerifier}
 * depending on the ceremony.
 *
 * Companion of {@see WebauthnOptionsResponse}: where the latter generates and
 * stores ceremony options, this one consumes the corresponding response from
 * the JSON request body, runs the validator and returns a typed
 * {@see WebauthnVerificationResult}. The user controller stays in charge of
 * the response (login, redirect, Signal API payload, etc.).
 *
 * Examples:
 *
 *     // Registration
 *     $result = $this->verifier
 *         ->forAttestation('example.com')
 *         ->verify($request);
 *     // $result->credentialRecord is already persisted
 *
 *     // Authentication
 *     $result = $this->verifier
 *         ->forAssertion('example.com')
 *         ->verify($request);
 *     // $result->credentialRecord has its counter / backup state updated
 */
final readonly class WebauthnResponseVerifier
{
    public function __construct(
        private SerializerInterface $serializer,
        private OptionsStorage $storage,
        private CredentialRecordRepositoryInterface $repository,
        private AuthenticatorAttestationResponseValidator $attestationValidator,
        private AuthenticatorAttestationResponseValidator $conditionalAttestationValidator,
        private AuthenticatorAssertionResponseValidator $assertionValidator,
    ) {
    }

    public function forAttestation(string $rpId): WebauthnAttestationVerifier
    {
        return new WebauthnAttestationVerifier(
            $this->serializer,
            $this->storage,
            $this->attestationValidator,
            $this->conditionalAttestationValidator,
            $this->repository,
            $rpId,
        );
    }

    public function forAssertion(string $rpId): WebauthnAssertionVerifier
    {
        return new WebauthnAssertionVerifier(
            $this->serializer,
            $this->storage,
            $this->assertionValidator,
            $this->repository,
            $rpId,
        );
    }
}
