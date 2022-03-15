<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Handler\CreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\SuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

final class AttestationControllerFactory
{
    public function __construct(
        private HttpMessageFactoryInterface $httpMessageFactory,
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private AuthenticatorAttestationResponseValidator $attestationResponseValidator,
        private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository
    ) {
    }

    public function createAttestationRequestController(
        UserEntityGuesser $userEntityGuesser,
        string $profile,
        OptionsStorage $optionStorage,
        CreationOptionsHandler $creationOptionsHandler
    ): AttestationRequestController {
        return new AttestationRequestController(
            $userEntityGuesser,
            $this->serializer,
            $this->validator,
            $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialCreationOptionsFactory,
            $profile,
            $optionStorage,
            $creationOptionsHandler
        );
    }

    public function createAttestationResponseController(
        OptionsStorage $optionStorage,
        SuccessHandler $successHandler,
        FailureHandler $failureHandler,
        $securedRelyingPartyIds
    ): AttestationResponseController {
        return new AttestationResponseController(
            $this->httpMessageFactory,
            $this->publicKeyCredentialLoader,
            $this->attestationResponseValidator,
            $this->publicKeyCredentialSourceRepository,
            $optionStorage,
            $successHandler,
            $failureHandler,
            $securedRelyingPartyIds
        );
    }
}
