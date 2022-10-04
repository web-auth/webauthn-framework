<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator as BaseAuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Event\AuthenticatorAttestationResponseValidationFailedEvent;
use Webauthn\Bundle\Event\AuthenticatorAttestationResponseValidationSucceededEvent;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\TokenBindingHandler;

final class AuthenticatorAttestationResponseValidator extends BaseAuthenticatorAttestationResponseValidator
{
    public function __construct(
        AttestationStatementSupportManager $attestationStatementSupportManager,
        PublicKeyCredentialSourceRepository $publicKeyCredentialSource,
        ?TokenBindingHandler $tokenBindingHandler,
        ExtensionOutputCheckerHandler $extensionOutputCheckerHandler
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

        parent::__construct(
            $attestationStatementSupportManager,
            $publicKeyCredentialSource,
            $tokenBindingHandler,
            $extensionOutputCheckerHandler
        );
    }

    protected function createAuthenticatorAttestationResponseValidationSucceededEvent(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ServerRequestInterface $request,
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
        ServerRequestInterface $request,
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
