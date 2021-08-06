<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Cose\Algorithm\Manager;
use JetBrains\PhpStorm\Pure;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
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
    #[Pure]
    public function __construct(PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, TokenBindingHandler $tokenBindingHandler, ExtensionOutputCheckerHandler $extensionOutputCheckerHandler, Manager $algorithmManager, private EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($publicKeyCredentialSourceRepository, $tokenBindingHandler, $extensionOutputCheckerHandler, $algorithmManager);
    }

    /**
     * {@inheritdoc}
     */
    public function check(string $credentialId, AuthenticatorAssertionResponse $authenticatorAssertionResponse, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, ServerRequestInterface $request, ?string $userHandle, array $securedRelyingPartyId = []): PublicKeyCredentialSource
    {
        try {
            $result = parent::check($credentialId, $authenticatorAssertionResponse, $publicKeyCredentialRequestOptions, $request, $userHandle, $securedRelyingPartyId);
            $this->eventDispatcher->dispatch(new AuthenticatorAssertionResponseValidationSucceededEvent(
                $credentialId,
                $authenticatorAssertionResponse,
                $publicKeyCredentialRequestOptions,
                $request,
                $userHandle,
                $result
            ));

            return $result;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new AuthenticatorAssertionResponseValidationFailedEvent(
                $credentialId,
                $authenticatorAssertionResponse,
                $publicKeyCredentialRequestOptions,
                $request,
                $userHandle,
                $throwable
            ));

            throw $throwable;
        }
    }
}
