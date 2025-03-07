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
        private OptionsStorage $optionStorage,
        private SerializerInterface $serializer,
        private AuthenticatorAttestationResponseValidator $attestationResponseValidator,
        private PublicKeyCredentialSourceRepositoryInterface $publicKeyCredentialSourceRepository
    ) {
    }

    public function createRequestController(
        PublicKeyCredentialCreationOptionsBuilder $optionsBuilder,
        UserEntityGuesser $userEntityGuesser,
        null|OptionsStorage $optionStorage,
        CreationOptionsHandler $creationOptionsHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        bool $hideExistingExcludedCredentials = false
    ): AttestationRequestController {
        if ($optionStorage !== null) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '5.2.0',
                'The parameter "$optionStorage" is deprecated since 5.2.0 and will be removed in 6.0.0. Please set "null" and use the global option storage instead.'
            );
        }
        return new AttestationRequestController(
            $optionsBuilder,
            $userEntityGuesser,
            $optionStorage ?? $this->optionStorage,
            $creationOptionsHandler,
            $failureHandler,
            $hideExistingExcludedCredentials
        );
    }

    public function createResponseController(
        null|OptionsStorage $optionStorage,
        SuccessHandler $successHandler,
        FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        null|AuthenticatorAttestationResponseValidator $attestationResponseValidator = null,
    ): AttestationResponseController {
        if ($optionStorage !== null) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '5.2.0',
                'The parameter "$optionStorage" is deprecated since 5.2.0 and will be removed in 6.0.0. Please set "null" and use the global option storage instead.'
            );
        }
        return new AttestationResponseController(
            $this->serializer,
            $attestationResponseValidator ?? $this->attestationResponseValidator,
            $this->publicKeyCredentialSourceRepository,
            $optionStorage ?? $this->optionStorage,
            $successHandler,
            $failureHandler,
        );
    }
}
