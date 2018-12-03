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

use Assert\Assertion;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Exception\SessionUnavailableException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Bundle\Security\Authentication\Token\PreWebauthnToken;
use Webauthn\PublicKeyCredentialRequestOptions;

class WebauthnListener implements ListenerInterface
{
    private $csrfTokenManager;
    private $tokenStorage;

    private $options;
    private $logger;
    private $authenticationManager;
    private $providerKey;
    private $httpUtils;

    private $sessionStrategy;
    private $dispatcher;
    private $successHandler;
    private $failureHandler;
    private $rememberMeServices;

    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, string $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = [], LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CsrfTokenManagerInterface $csrfTokenManager = null)
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->sessionStrategy = $sessionStrategy;
        $this->providerKey = $providerKey;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
        $this->options = $options;
        $this->logger = $logger;
        $this->dispatcher = $dispatcher;
        $this->httpUtils = $httpUtils;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->tokenStorage = $tokenStorage;
    }

    public function setRememberMeServices(RememberMeServicesInterface $rememberMeServices)
    {
        $this->rememberMeServices = $rememberMeServices;
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        //Only check POST requests
        if (!$request->isMethod('POST')) {
            return;
        }

        switch (true) {
            case $this->httpUtils->checkRequestPath($request, $this->options['check_path']):
                return $this->handleCheckAssertionPath($event);
            case $this->httpUtils->checkRequestPath($request, $this->options['assertion_path']):
                return $this->handleCheckUsernamePath($event);

            return;
        }
    }

    private function handleCheckAssertionPath(GetResponseEvent $event)
    {
    }

    private function handleCheckUsernamePath(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        Assertion::true($request->hasSession(), 'This authentication method requires a session.');
        try {
            /*if ($this->options['require_previous_session'] && !$request->hasPreviousSession()) {
                throw new SessionUnavailableException('Your session has timed out, or you have disabled cookies.');
            }*/
            $returnValue = $this->attemptAuthentication($request);
            $this->sessionStrategy->onAuthentication($request, $returnValue);
            $response = $this->onUsernameSuccess($request, $returnValue);
        } catch (AuthenticationException $e) {
            $response = $this->onFailure($request, $e);
        }

        $event->setResponse($response);
    }

    private function onFailure(Request $request, AuthenticationException $failed)
    {
        if (null !== $this->logger) {
            $this->logger->info('Authentication request failed.', ['exception' => $failed]);
        }

        $token = $this->tokenStorage->getToken();
        if ($token instanceof UsernamePasswordToken && $this->providerKey === $token->getProviderKey()) {
            $this->tokenStorage->setToken(null);
        }

        $response = $this->failureHandler->onAuthenticationFailure($request, $failed);

        if (!$response instanceof Response) {
            throw new \RuntimeException('Authentication Failure Handler did not return a Response.');
        }

        return $response;
    }

    private function onUsernameSuccess(Request $request, TokenInterface $token): Response
    {
        if (null !== $this->logger) {
            $this->logger->info('User has been authenticated successfully.', ['username' => $token->getUsername()]);
        }

        $this->tokenStorage->setToken($token);

        $session = $request->getSession();
        $session->remove(Security::AUTHENTICATION_ERROR);
        $session->remove(Security::LAST_USERNAME);

        if (null !== $this->dispatcher) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN, $loginEvent);
        }

        $response = $this->httpUtils->createRedirectResponse($request, $this->options['assertion_path']);
        //$response = $this->successHandler->onAuthenticationSuccess($request, $token);
        if (null !== $this->rememberMeServices) {
            $this->rememberMeServices->loginSuccess($request, $response, $token);
        }

        return $response;
    }

    private function attemptAuthentication(Request $request): TokenInterface
    {
        if (null !== $this->csrfTokenManager) {
            $csrfToken = $request->request->get($this->options['csrf_parameter']);
            if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['csrf_token_id'], $csrfToken))) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }

        return $this->processWithUsername($request);
    }

    private function processWithUsername(Request $request): PreWebauthnToken
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
            $this->options['relaying_party']['id'],
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
