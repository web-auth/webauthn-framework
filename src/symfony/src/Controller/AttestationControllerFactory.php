<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\CredentialOptionsBuilder\PublicKeyCredentialCreationOptionsBuilder;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Handler\CreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\SuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;

final readonly class AttestationControllerFactory
{
    public function __construct(
        private SerializerInterface $serializer,
        private AuthenticatorAttestationResponseValidator $attestationResponseValidator,
        private PublicKeyCredentialSourceRepositoryInterface $publicKeyCredentialSourceRepository
    ) {
    }

    public function createRequestController(
        PublicKeyCredentialCreationOptionsBuilder $optionsBuilder,
        UserEntityGuesser $userEntityGuesser,
        OptionsStorage $optionStorage,
        CreationOptionsHandler $creationOptionsHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
    ): AttestationRequestController {
        return new AttestationRequestController(
            $optionsBuilder,
            $userEntityGuesser,
            $optionStorage,
            $creationOptionsHandler,
            $failureHandler
        );
    }

    public function createResponseController(
        OptionsStorage $optionStorage,
        SuccessHandler $successHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        null|AuthenticatorAttestationResponseValidator $attestationResponseValidator = null,
    ): AttestationResponseController {
        return new AttestationResponseController(
            $this->serializer,
            $attestationResponseValidator ?? $this->attestationResponseValidator,
            $this->publicKeyCredentialSourceRepository,
            $optionStorage,
            $successHandler,
            $failureHandler,
        );
    }
}
