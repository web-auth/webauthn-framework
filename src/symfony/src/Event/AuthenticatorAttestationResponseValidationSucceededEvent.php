<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Psr\Http\Message\ServerRequestInterface;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Event\AuthenticatorAttestationResponseValidationSucceededEvent as BaseAuthenticatorAttestationResponseValidationSucceededEvent;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;
use function sprintf;

/**
 * @deprecated since 4.3.0, use {@link \Webauthn\Event\AuthenticatorAttestationResponseValidationSucceededEvent} instead.
 */
class AuthenticatorAttestationResponseValidationSucceededEvent extends BaseAuthenticatorAttestationResponseValidationSucceededEvent
{
    public function __construct(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ServerRequestInterface|string $request,
        PublicKeyCredentialSource $publicKeyCredentialSource
    ) {
        trigger_deprecation(
            'web-auth/webauthn-symfony-bundle',
            '4.3.0',
            sprintf(
                'The class "%s" is deprecated since 4.3.0 and will be removed in 5.0.0. Please use "%s" instead.',
                self::class,
                BaseAuthenticatorAttestationResponseValidationSucceededEvent::class
            )
        );
        parent::__construct($authenticatorAttestationResponse, $publicKeyCredentialCreationOptions, $request, $publicKeyCredentialSource);
    }
}
