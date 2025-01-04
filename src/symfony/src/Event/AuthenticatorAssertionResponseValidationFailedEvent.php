<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Event\AuthenticatorAssertionResponseValidationFailedEvent as BaseAuthenticatorAssertionResponseValidationFailedEvent;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use function sprintf;

/**
 * @deprecated since 4.3.0, use {@link \Webauthn\Event\AuthenticatorAssertionResponseValidationFailedEvent} instead.
 */
class AuthenticatorAssertionResponseValidationFailedEvent extends BaseAuthenticatorAssertionResponseValidationFailedEvent
{
    public function __construct(
        string|PublicKeyCredentialSource $credentialId,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ServerRequestInterface|string $request,
        ?string $userHandle,
        Throwable $throwable
    ) {
        trigger_deprecation(
            'web-auth/webauthn-symfony-bundle',
            '4.3.0',
            sprintf(
                'The class "%s" is deprecated since 4.3.0 and will be removed in 5.0.0. Please use "%s" instead.',
                self::class,
                BaseAuthenticatorAssertionResponseValidationFailedEvent::class
            )
        );

        parent::__construct(
            $credentialId,
            $authenticatorAssertionResponse,
            $publicKeyCredentialRequestOptions,
            $request,
            $userHandle,
            $throwable
        );
    }
}
