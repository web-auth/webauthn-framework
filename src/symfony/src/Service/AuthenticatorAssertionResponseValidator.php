<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Service;

use Cose\Algorithm\Manager;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator as BaseAuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Event\AuthenticatorAssertionResponseValidationFailedEvent;
use Webauthn\Bundle\Event\AuthenticatorAssertionResponseValidationSucceededEvent;
use Webauthn\Counter\CounterChecker;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\TokenBinding\TokenBindingHandler;

final class AuthenticatorAssertionResponseValidator extends BaseAuthenticatorAssertionResponseValidator
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct(PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, TokenBindingHandler $tokenBindingHandler, ExtensionOutputCheckerHandler $extensionOutputCheckerHandler, Manager $algorithmManager, EventDispatcherInterface $eventDispatcher, ?CounterChecker $counterChecker = null, ?LoggerInterface $logger = null)
    {
        parent::__construct($publicKeyCredentialSourceRepository, $tokenBindingHandler, $extensionOutputCheckerHandler, $algorithmManager, $counterChecker, $logger);
        $this->eventDispatcher = $eventDispatcher;
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
