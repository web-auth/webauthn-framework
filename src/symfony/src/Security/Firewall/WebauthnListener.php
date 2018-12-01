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

namespace Webauthn\Bundle\Security\Firewall;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Security\Authentication\Token\PreWebauthnToken;
use Webauthn\PublicKeyCredentialRequestOptions;

class WebauthnListener extends AbstractAuthenticationListener
{
    private $csrfTokenManager;
    private $tokenStorage;

    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, string $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = [], LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CsrfTokenManagerInterface $csrfTokenManager = null)
    {
        parent::__construct($tokenStorage, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge([
            'username_parameter' => '_username',
            'csrf_parameter' => '_csrf_token',
            'csrf_token_id' => 'authenticate',
            'rp_id' => null,
            'rp_name' => 'Webauthn Security',
            'rp_icon' => null,
            'timeout' => 60000,
            'challenge_length' => 32,
            'user_verification' => PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        ], $options), $logger, $dispatcher);

        $this->csrfTokenManager = $csrfTokenManager;
        $this->tokenStorage = $tokenStorage;
    }

    protected function requiresAuthentication(Request $request)
    {
        if (!$request->isMethod('POST')) {
            return false;
        }

        return parent::requiresAuthentication($request);
    }

    protected function attemptAuthentication(Request $request)
    {
        if (null !== $this->csrfTokenManager) {
            $csrfToken = $request->request->get($this->options['csrf_parameter']);

            if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['csrf_token_id'], $csrfToken))) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }

        $token = $this->tokenStorage->getToken();
        if ($token instanceof PreWebauthnToken) {
            return $this->processWithAssertion($request, $token);
        }

        return $this->processWithUsername($request);
    }

    private function processWithUsername(Request $request)
    {
        $username = $request->request->get($this->options['username_parameter']);

        if (!\is_string($username)) {
            throw new BadRequestHttpException(sprintf('The key "%s" must be a string, "%s" given.', $this->options['username_parameter'], \gettype($username)));
        }

        $username = trim($username);

        if (\mb_strlen($username) > Security::MAX_USERNAME_LENGTH) {
            throw new BadCredentialsException('Invalid username.');
        }

        $request->getSession()->set(Security::LAST_USERNAME, $username);

        return new PreWebauthnToken($username, new PublicKeyCredentialRequestOptions(
            random_bytes($this->options['challenge_length']),
            $this->options['timeout'],
            $this->options['rp_id'],
            [],
            $this->options['user_verification'],
            new AuthenticationExtensionsClientInputs()
        ), $this->providerKey);
    }

    private function processWithAssertion(Request $request, PreWebauthnToken $token)
    {
        throw new BadRequestHttpException(sprintf('The key "%s" must be a string, "%s" given.', $this->options['username_parameter'], \gettype($username)));
        /*$username = $request->request->get($this->options['username_parameter']);

        if (!\is_string($username)) {
            throw new BadRequestHttpException(sprintf('The key "%s" must be a string, "%s" given.', $this->options['username_parameter'], \gettype($username)));
        }

        $username = trim($username);

        if (\mb_strlen($username) > Security::MAX_USERNAME_LENGTH) {
            throw new BadCredentialsException('Invalid username.');
        }

        $request->getSession()->set(Security::LAST_USERNAME, $username);

        $token

        return new

        return $this->authenticationManager->authenticate(new UsernamePasswordToken($username, $password, $this->providerKey));*/
    }
}
