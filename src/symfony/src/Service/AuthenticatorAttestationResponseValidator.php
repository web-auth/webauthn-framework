<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
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
        ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($attestationStatementSupportManager, $publicKeyCredentialSource, $tokenBindingHandler, $extensionOutputCheckerHandler);
    }

    public function check(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        ServerRequestInterface $request,
        array $securedRelyingPartyId = []
    ): PublicKeyCredentialSource {
        try {
            $result = parent::check(
                $authenticatorAttestationResponse,
                $publicKeyCredentialCreationOptions,
                $request,
                $securedRelyingPartyId
            );
            $this->eventDispatcher->dispatch(new AuthenticatorAttestationResponseValidationSucceededEvent(
                $authenticatorAttestationResponse,
                $publicKeyCredentialCreationOptions,
                $request,
                $result
            ));

            return $result;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new AuthenticatorAttestationResponseValidationFailedEvent(
                $authenticatorAttestationResponse,
                $publicKeyCredentialCreationOptions,
                $request,
                $throwable
            ));

            throw $throwable;
        }
    }
}
