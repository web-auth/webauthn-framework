<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator as BaseAuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Event\AuthenticatorAttestationResponseValidationSucceededEvent;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\Event\AuthenticatorAttestationResponseValidationFailedEvent;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TokenBinding\TokenBindingHandler;
use function sprintf;

/**
 * @deprecated since 4.3.0. The class is deprecated and will be removed in 5.0.0. Please use "Webauthn\BaseAuthenticatorAttestationResponseValidator" instead.
 */
final class AuthenticatorAttestationResponseValidator extends BaseAuthenticatorAttestationResponseValidator
{
    public function __construct(
        AttestationStatementSupportManager $attestationStatementSupportManager,
        ?TokenBindingHandler $tokenBindingHandler,
        ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        ?EventDispatcherInterface $eventDispatcher,
        null|CeremonyStepManager $ceremonyStepManager = null
    ) {
        trigger_deprecation(
            'web-auth/webauthn-symfony-bundle',
            '4.3.0',
            sprintf(
                'The class "%s" is deprecated since 4.3.0 and will be removed in 5.0.0. Please use "%s" instead.',
                self::class,
                BaseAuthenticatorAttestationResponseValidator::class
            )
        );
        parent::__construct($attestationStatementSupportManager, null, $tokenBindingHandler, $extensionOutputCheckerHandler, $eventDispatcher, $ceremonyStepManager);
    }

    protected function createAuthenticatorAttestationResponseValidationSucceededEvent(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ServerRequestInterface|string $request,
        PublicKeyCredentialSource $publicKeyCredentialSource
    ): AuthenticatorAttestationResponseValidationSucceededEvent {
        return new AuthenticatorAttestationResponseValidationSucceededEvent(
            $authenticatorAttestationResponse,
            $publicKeyCredentialCreationOptions,
            $request,
            $publicKeyCredentialSource
        );
    }

    protected function createAuthenticatorAttestationResponseValidationFailedEvent(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ServerRequestInterface|string $request,
        Throwable $throwable
    ): AuthenticatorAttestationResponseValidationFailedEvent {
        return new AuthenticatorAttestationResponseValidationFailedEvent(
            $authenticatorAttestationResponse,
            $publicKeyCredentialCreationOptions,
            $request,
            $throwable
        );
    }
}
