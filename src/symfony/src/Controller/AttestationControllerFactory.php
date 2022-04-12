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
        private readonly HttpMessageFactoryInterface $httpMessageFactory,
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private readonly PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private readonly AuthenticatorAttestationResponseValidator $attestationResponseValidator,
        private readonly PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository
    ) {
    }

    public function createAttestationRequestController(
        UserEntityGuesser $userEntityGuesser,
        string $profile,
        OptionsStorage $optionStorage,
        CreationOptionsHandler $creationOptionsHandler,
        FailureHandler $failureHandler,
    ): AttestationRequestController {
        return new AttestationRequestController(
            $userEntityGuesser,
            $this->serializer,
            $this->validator,
            $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialCreationOptionsFactory,
            $profile,
            $optionStorage,
            $creationOptionsHandler,
            $failureHandler
        );
    }

    /**
     * @param string[] $securedRelyingPartyIds
     */
    public function createAttestationResponseController(
        OptionsStorage $optionStorage,
        SuccessHandler $successHandler,
        FailureHandler $failureHandler,
        array $securedRelyingPartyIds
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
