<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\MetadataService\CanLogData;

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
 *
 *     // Per-controller origin override (mirrors the legacy
 *     // controllers[].allowed_origins YAML option)
 *     $result = $this->verifier
 *         ->forAttestation('example.com')
 *         ->withAllowedOrigins('https://app.example.com')
 *         ->verify($request);
 */
final class WebauthnResponseVerifier implements CanLogData, CanDispatchEvents
{
    private LoggerInterface $logger;

    private EventDispatcherInterface $eventDispatcher;

    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly OptionsStorage $storage,
        private readonly CredentialRecordRepositoryInterface $repository,
        private readonly AuthenticatorAttestationResponseValidator $attestationValidator,
        private readonly AuthenticatorAttestationResponseValidator $conditionalAttestationValidator,
        private readonly AuthenticatorAssertionResponseValidator $assertionValidator,
        private readonly CeremonyStepManagerFactory $ceremonyStepManagerFactory,
    ) {
        $this->logger = new NullLogger();
        $this->eventDispatcher = new NullEventDispatcher();
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    public function forAttestation(string $rpId): WebauthnAttestationVerifier
    {
        $verifier = new WebauthnAttestationVerifier(
            $this->serializer,
            $this->storage,
            $this->attestationValidator,
            $this->conditionalAttestationValidator,
            $this->repository,
            $this->ceremonyStepManagerFactory,
            $rpId,
        );
        $verifier->setLogger($this->logger);
        $verifier->setEventDispatcher($this->eventDispatcher);

        return $verifier;
    }

    public function forAssertion(string $rpId): WebauthnAssertionVerifier
    {
        $verifier = new WebauthnAssertionVerifier(
            $this->serializer,
            $this->storage,
            $this->assertionValidator,
            $this->repository,
            $this->ceremonyStepManagerFactory,
            $rpId,
        );
        $verifier->setLogger($this->logger);
        $verifier->setEventDispatcher($this->eventDispatcher);

        return $verifier;
    }
}
