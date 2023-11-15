<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\CredentialOptionsBuilder\ProfileBasedCreationOptionsBuilder;
use Webauthn\Bundle\CredentialOptionsBuilder\PublicKeyCredentialCreationOptionsBuilder;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
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
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private readonly null|PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private readonly AuthenticatorAttestationResponseValidator $attestationResponseValidator,
        private readonly PublicKeyCredentialSourceRepository|PublicKeyCredentialSourceRepositoryInterface $publicKeyCredentialSourceRepository
    ) {
        if ($this->publicKeyCredentialLoader !== null) {
            trigger_deprecation(
                'web-auth/webauthn-bundle',
                '4.8.0',
                'The argument "$publicKeyCredentialLoader" is deprecated since 4.5.0 and will be removed in 5.0.0. Please set null instead; the serializer will be used instead.'
            );
        }
    }

    /**
     * @deprecated since 4.5.0 and will be removed in 5.0.0. Please use createResponseController instead.
     * @infection-ignore-all
     */
    public function createAttestationRequestController(
        UserEntityGuesser $userEntityGuesser,
        string $profile,
        OptionsStorage $optionStorage,
        CreationOptionsHandler $creationOptionsHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
    ): AttestationRequestController {
        $optionsBuilder = new ProfileBasedCreationOptionsBuilder(
            $this->serializer,
            $this->validator,
            $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialCreationOptionsFactory,
            $profile
        );
        return $this->createRequestController(
            $optionsBuilder,
            $userEntityGuesser,
            $optionStorage,
            $creationOptionsHandler,
            $failureHandler
        );
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

    /**
     * @deprecated since 4.5.0 and will be removed in 5.0.0. Please use createResponseController instead.
     * @infection-ignore-all
     */
    public function createAttestationResponseController(
        OptionsStorage $optionStorage,
        SuccessHandler $successHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler
    ): AttestationResponseController {
        return $this->createResponseController($optionStorage, $successHandler, $failureHandler);
    }

    /**
     * @param null|string[] $securedRelyingPartyIds
     */
    public function createResponseController(
        OptionsStorage $optionStorage,
        SuccessHandler $successHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        null|array $securedRelyingPartyIds = null,
        null|AuthenticatorAttestationResponseValidator $attestationResponseValidator = null,
    ): AttestationResponseController {
        return new AttestationResponseController(
            $this->publicKeyCredentialLoader ?? $this->serializer,
            $attestationResponseValidator ?? $this->attestationResponseValidator,
            $this->publicKeyCredentialSourceRepository,
            $optionStorage,
            $successHandler,
            $failureHandler,
            $securedRelyingPartyIds
        );
    }
}
