<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

final class AssertionControllerFactory
{
    public function __construct(
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory,
        private PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private AuthenticatorAssertionResponseValidator $attestationResponseValidator,
        private LoggerInterface $logger,
        private PublicKeyCredentialUserEntityRepository $publicKeyCredentialUserEntityRepository,
        private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository
    ) {
    }

    public function createAssertionRequestController(
        string $profile,
        OptionsStorage $optionStorage,
        RequestOptionsHandler $optionsHandler,
    ): AssertionRequestController {
        return new AssertionRequestController(
            $this->serializer,
            $this->validator,
            $this->publicKeyCredentialUserEntityRepository,
            $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialRequestOptionsFactory,
            $profile,
            $optionStorage,
            $optionsHandler,
            $this->logger
        );
    }

    public function createAssertionResponseController(
        OptionsStorage $optionStorage,
        HttpMessageFactoryInterface $httpMessageFactory,
    ): AssertionResponseController {
        return new AssertionResponseController(
            $httpMessageFactory,
            $this->publicKeyCredentialLoader,
            $this->attestationResponseValidator,
            $this->logger,
            $optionStorage
        );
    }
}
