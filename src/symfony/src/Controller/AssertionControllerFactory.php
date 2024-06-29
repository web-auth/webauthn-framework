<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedRequestOptionsBuilder;
use Webauthn\Bundle\CredentialOptionsBuilder\PublicKeyCredentialRequestOptionsBuilder;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\SuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\FakeCredentialGenerator;
use Webauthn\MetadataService\CanLogData;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

final class AssertionControllerFactory implements CanLogData
{
    private LoggerInterface $logger;

    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory,
        private readonly null|PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private readonly AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator,
        private readonly PublicKeyCredentialUserEntityRepositoryInterface $publicKeyCredentialUserEntityRepository,
        private readonly PublicKeyCredentialSourceRepository|PublicKeyCredentialSourceRepositoryInterface $publicKeyCredentialSourceRepository,
        private readonly null|FakeCredentialGenerator $fakeCredentialGenerator = null,
    ) {
        if ($this->publicKeyCredentialLoader !== null) {
            trigger_deprecation(
                'web-auth/webauthn-bundle',
                '4.8.0',
                'The argument "$publicKeyCredentialLoader" is deprecated since 4.5.0 and will be removed in 5.0.0. Please set null instead; the serializer will be used instead.'
            );
        }
        $this->logger = new NullLogger();
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * @deprecated since 4.5.0 and will be removed in 5.0.0. Please use createRequestController instead.
     * @infection-ignore-all
     */
    public function createAssertionRequestController(
        string $profile,
        OptionsStorage $optionStorage,
        RequestOptionsHandler $optionsHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler
    ): AssertionRequestController {
        $optionsBuilder = new ProfileBasedRequestOptionsBuilder(
            $this->serializer,
            $this->validator,
            $this->publicKeyCredentialUserEntityRepository,
            $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialRequestOptionsFactory,
            $profile,
            $this->fakeCredentialGenerator,
        );

        return $this->createRequestController($optionsBuilder, $optionStorage, $optionsHandler, $failureHandler);
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
            $this->logger,
        );
    }

    /**
     * @param string[] $securedRelyingPartyIds
     * @deprecated since 4.5.0 and will be removed in 5.0.0. Please use createResponseController instead.
     * @infection-ignore-all
     */
    public function createAssertionResponseController(
        OptionsStorage $optionStorage,
        SuccessHandler $successHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        array $securedRelyingPartyIds
    ): AssertionResponseController {
        return $this->createResponseController(
            $optionStorage,
            $successHandler,
            $failureHandler,
            $securedRelyingPartyIds
        );
    }

    /**
     * @param null|string[] $securedRelyingPartyIds
     */
    public function createResponseController(
        OptionsStorage $optionStorage,
        SuccessHandler $successHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        null|array $securedRelyingPartyIds = null,
        null|AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator = null,
    ): AssertionResponseController {
        return new AssertionResponseController(
            $this->publicKeyCredentialLoader ?? $this->serializer,
            $authenticatorAssertionResponseValidator ?? $this->authenticatorAssertionResponseValidator,
            $this->logger,
            $optionStorage,
            $successHandler,
            $failureHandler,
            $securedRelyingPartyIds,
            $this->publicKeyCredentialSourceRepository
        );
    }
}
