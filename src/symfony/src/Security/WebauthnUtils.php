<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security;

use Assert\Assertion;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Model\CanHaveRegisteredSecurityDevices;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

class WebauthnUtils
{
    public const PUBLIC_KEY_CREDENTIAL_REQUEST_OPTIONS = '_webauthn.public_key_credential_request_options';

    private $authenticationUtils;
    private $requestStack;

    public function __construct(RequestStack $requestStack)
    {
        $this->requestStack = $requestStack;
        $this->authenticationUtils = new AuthenticationUtils($requestStack);
    }

    public function getLastAuthenticationError(bool $clearSession = true): ?AuthenticationException
    {
        return $this->authenticationUtils->getLastAuthenticationError($clearSession);
    }

    public function getLastUsername(): string
    {
        return $this->authenticationUtils->getLastUsername();
    }

    public function generateRequestFor(UserInterface $user, int $challengeLength = 16, int $timeout = 60000, string $rpId = null, string $userVerification = PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED, ?AuthenticationExtensionsClientInputs $extensions = null): PublicKeyCredentialRequestOptions
    {
        Assertion::min($timeout, 1, 'Invalid timeout');
        Assertion::min($challengeLength, 1, 'Invalid challenge length');
        if (!$user instanceof CanHaveRegisteredSecurityDevices) {
            throw new \InvalidArgumentException('The user must implement the interface "Webauthn\Bundle\Model\CanHaveRegisteredSecurityDevices"');
        }

        $credentials = [];
        foreach ($user->getSecurityDeviceCredentialIds() as $publicKeyCredentialDescriptor) {
            Assertion::isInstanceOf($publicKeyCredentialDescriptor, PublicKeyCredentialDescriptor::class, \Safe\sprintf('Invalid credential. Must be of type "Webauthn\PublicKeyCredentialDescriptor", got "%s".', \gettype($publicKeyCredentialDescriptor)));
            $credentials[] = $publicKeyCredentialDescriptor;
        }

        $request = $this->getRequest();
        $PublicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions(
            random_bytes($challengeLength),
            $timeout,
            $rpId ?? $request->getHost(),
            $credentials,
            $userVerification,
            $extensions
        );
        $request->getSession()->set(self::PUBLIC_KEY_CREDENTIAL_REQUEST_OPTIONS, $PublicKeyCredentialRequestOptions);

        return $PublicKeyCredentialRequestOptions;
    }

    private function getRequest(): Request
    {
        $request = $this->requestStack->getCurrentRequest();
        if (null === $request) {
            throw new \LogicException('Request should exist so it can be processed for error.');
        }

        return $request;
    }
}
