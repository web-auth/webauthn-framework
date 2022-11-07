<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Cose\Algorithm\Manager;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator as BaseAuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Event\AuthenticatorAssertionResponseValidationFailedEvent;
use Webauthn\Bundle\Event\AuthenticatorAssertionResponseValidationSucceededEvent;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\TokenBindingHandler;

final class AuthenticatorAssertionResponseValidator extends BaseAuthenticatorAssertionResponseValidator
{
    public function __construct(
        PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        ?TokenBindingHandler $tokenBindingHandler,
        ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        ?Manager $algorithmManager
    ) {
        trigger_deprecation(
            'web-auth/webauthn-symfony-bundle',
            '4.3.0',
            sprintf(
                'The class "%s" is deprecated since 4.3.0 and will be removed in 5.0.0. Please use "%s" instead.',
                self::class,
                BaseAuthenticatorAssertionResponseValidator::class
            )
        );

        parent::__construct(
            $publicKeyCredentialSourceRepository,
            $tokenBindingHandler,
            $extensionOutputCheckerHandler,
            $algorithmManager
        );
    }

    protected function createAuthenticatorAssertionResponseValidationSucceededEvent(
        string $credentialId,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ServerRequestInterface $request,
        ?string $userHandle,
        PublicKeyCredentialSource $publicKeyCredentialSource
    ): AuthenticatorAssertionResponseValidationSucceededEvent {
        return new AuthenticatorAssertionResponseValidationSucceededEvent(
            $credentialId,
            $authenticatorAssertionResponse,
            $publicKeyCredentialRequestOptions,
            $request,
            $userHandle,
            $publicKeyCredentialSource
        );
    }

    protected function createAuthenticatorAssertionResponseValidationFailedEvent(
        string $credentialId,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ServerRequestInterface $request,
        ?string $userHandle,
        Throwable $throwable
    ): AuthenticatorAssertionResponseValidationFailedEvent {
        return new AuthenticatorAssertionResponseValidationFailedEvent(
            $credentialId,
            $authenticatorAssertionResponse,
            $publicKeyCredentialRequestOptions,
            $request,
            $userHandle,
            $throwable
        );
    }
}
