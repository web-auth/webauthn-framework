<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\CredentialOptionsBuilder\PublicKeyCredentialRequestOptionsBuilder;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\SuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\MetadataService\CanLogData;

final class AssertionControllerFactory implements CanLogData
{
    private LoggerInterface $logger;

    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator,
        private readonly PublicKeyCredentialSourceRepositoryInterface $publicKeyCredentialSourceRepository
    ) {
        $this->logger = new NullLogger();
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function createRequestController(
        PublicKeyCredentialRequestOptionsBuilder $optionsBuilder,
        OptionsStorage $optionStorage,
        RequestOptionsHandler $optionsHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler
    ): AssertionRequestController {
        return new AssertionRequestController(
            $optionsBuilder,
            $optionStorage,
            $optionsHandler,
            $failureHandler,
            $this->logger
        );
    }

    public function createResponseController(
        OptionsStorage $optionStorage,
        SuccessHandler $successHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        null|AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator = null,
    ): AssertionResponseController {
        return new AssertionResponseController(
            $this->serializer,
            $authenticatorAssertionResponseValidator ?? $this->authenticatorAssertionResponseValidator,
            $this->logger,
            $optionStorage,
            $successHandler,
            $failureHandler,
            $this->publicKeyCredentialSourceRepository
        );
    }
}
