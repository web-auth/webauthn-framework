<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Event\AuthenticatorAttestationResponseValidationFailedEvent as BaseAuthenticatorAttestationResponseValidationFailedEvent;
use Webauthn\PublicKeyCredentialCreationOptions;
use function sprintf;

/**
 * @deprecated since 4.3.0, use {@link \Webauthn\Event\AuthenticatorAttestationResponseValidationFailedEvent} instead.
 */
class AuthenticatorAttestationResponseValidationFailedEvent extends BaseAuthenticatorAttestationResponseValidationFailedEvent
{
    public function __construct(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ServerRequestInterface|string $request,
        Throwable $throwable
    ) {
        trigger_deprecation(
            'web-auth/webauthn-symfony-bundle',
            '4.3.0',
            sprintf(
                'The class "%s" is deprecated since 4.3.0 and will be removed in 5.0.0. Please use "%s" instead.',
                self::class,
                BaseAuthenticatorAttestationResponseValidationFailedEvent::class
            )
        );
        parent::__construct($authenticatorAttestationResponse, $publicKeyCredentialCreationOptions, $request, $throwable);
    }
}
