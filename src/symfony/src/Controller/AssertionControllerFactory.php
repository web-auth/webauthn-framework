<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedRequestOptionsBuilder;
use Webauthn\Bundle\CredentialOptionsBuilder\PublicKeyCredentialRequestOptionsBuilder;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\SuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

final class AssertionControllerFactory
{
    private LoggerInterface $logger;

    public function __construct(
        private readonly HttpMessageFactoryInterface              $httpMessageFactory,
        private readonly SerializerInterface                      $serializer,
        private readonly ValidatorInterface                       $validator,
        private readonly PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory,
        private readonly PublicKeyCredentialLoader                $publicKeyCredentialLoader,
        private readonly AuthenticatorAssertionResponseValidator  $attestationResponseValidator,
        private readonly PublicKeyCredentialUserEntityRepository  $publicKeyCredentialUserEntityRepository,
        private readonly PublicKeyCredentialSourceRepository      $publicKeyCredentialSourceRepository
    )
    {
        $this->logger = new NullLogger();
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * @deprecated since 4.5.0 and will be removed in 5.0.0. Please use createRequestController instead.
     */
    public function createAssertionRequestController(
        string                                               $profile,
        OptionsStorage                                       $optionStorage,
        RequestOptionsHandler                                $optionsHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler
    ): AssertionRequestController
    {
        $extractor = new ProfileBasedRequestOptionsBuilder(
            $this->serializer,
            $this->validator,
            $this->publicKeyCredentialUserEntityRepository,
            $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialRequestOptionsFactory,
            $profile,
        );

        return $this->createRequestController($extractor, $optionStorage, $optionsHandler, $failureHandler);
    }

    public function createRequestController(
        PublicKeyCredentialRequestOptionsBuilder             $extractor,
        OptionsStorage                                       $optionStorage,
        RequestOptionsHandler                                $optionsHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler
    ): AssertionRequestController
    {
        return new AssertionRequestController(
            $extractor,
            $optionStorage,
            $optionsHandler,
            $failureHandler,
            $this->logger
        );
    }

    /**
     * @param string[] $securedRelyingPartyIds
     * @deprecated since 4.5.0 and will be removed in 5.0.0. Please use createResponseController instead.
     */
    public function createAssertionResponseController(
        OptionsStorage                                       $optionStorage,
        SuccessHandler                                       $successHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        array                                                $securedRelyingPartyIds
    ): AssertionResponseController
    {
        return $this->createResponseController(
            $optionStorage,
            $successHandler,
            $failureHandler,
            $securedRelyingPartyIds
        );
    }

    /**
     * @param string[] $securedRelyingPartyIds
     */
    public function createResponseController(
        OptionsStorage                                       $optionStorage,
        SuccessHandler                                       $successHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        array                                                $securedRelyingPartyIds
    ): AssertionResponseController
    {
        return new AssertionResponseController(
            $this->httpMessageFactory,
            $this->publicKeyCredentialLoader,
            $this->attestationResponseValidator,
            $this->logger,
            $optionStorage,
            $successHandler,
            $failureHandler,
            $securedRelyingPartyIds
        );
    }
}
