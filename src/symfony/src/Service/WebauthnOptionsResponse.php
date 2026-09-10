<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\FakeCredentialGenerator;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Single, autowired entry point that produces a fluent
 * {@see WebauthnCreationOptionsBuilder} or {@see WebauthnRequestOptionsBuilder}
 * depending on the ceremony.
 *
 * The required pieces (`rpId` and, for creation, the user entity or a
 * {@see UserEntityGuesser}) are passed straight to the factory method. Every
 * other field has a sensible default and is fluently overridable on the
 * returned builder. The terminal `build($request)` step persists the options
 * via the bundle's `OptionsStorage` and returns a `JsonResponse` ready to ship.
 *
 * Examples:
 *
 *     // Registration (user is required, passed positionally)
 *     return $this->options
 *         ->forCreation('example.com', $this->newUserGuesser)
 *         ->build($request);
 *
 *     // Authentication, userless (passkeys discoverable)
 *     return $this->options
 *         ->forRequest('example.com')
 *         ->build($request);
 *
 *     // Authentication, user already known: attach via withUser()
 *     return $this->options
 *         ->forRequest('example.com')
 *         ->withUser($userEntity)
 *         ->build($request);
 */
final readonly class WebauthnOptionsResponse
{
    public function __construct(
        private OptionsStorage $storage,
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private CredentialRecordRepositoryInterface $credentialRepository,
        private ?FakeCredentialGenerator $fakeCredentialGenerator = null,
    ) {
    }

    public function forCreation(
        string $rpId,
        PublicKeyCredentialUserEntity|UserEntityGuesser $user,
    ): WebauthnCreationOptionsBuilder {
        return new WebauthnCreationOptionsBuilder(
            $this->storage,
            $this->serializer,
            $this->validator,
            $this->credentialRepository,
            $rpId,
            $user,
        );
    }

    public function forRequest(string $rpId): WebauthnRequestOptionsBuilder
    {
        return new WebauthnRequestOptionsBuilder(
            $this->storage,
            $this->serializer,
            $this->validator,
            $this->credentialRepository,
            $rpId,
            $this->fakeCredentialGenerator,
        );
    }
}
