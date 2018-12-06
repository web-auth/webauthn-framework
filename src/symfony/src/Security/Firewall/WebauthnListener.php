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
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Exception\SessionUnavailableException;
use Symfony\Component\Security\Core\Role\SwitchUserRole;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Security\Authentication\Token\PreWebauthnToken;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\PublicKeyCredentialLoader;
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

    /**
     * @var RememberMeServicesInterface
     */
    private $rememberMeServices;

    private $publicKeyCredentialLoader;

    private $authenticatorAssertionResponseValidator;

    public function __construct(PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator, TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, string $providerKey, array $options = [], LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CsrfTokenManagerInterface $csrfTokenManager = null)
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->sessionStrategy = $sessionStrategy;
        $this->providerKey = $providerKey;
        $this->options = $options;
        $this->logger = $logger;
        $this->dispatcher = $dispatcher;
        $this->httpUtils = $httpUtils;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->tokenStorage = $tokenStorage;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->authenticatorAssertionResponseValidator = $authenticatorAssertionResponseValidator;
    }

    public function setRememberMeServices(RememberMeServicesInterface $rememberMeServices)
    {
        $this->rememberMeServices = $rememberMeServices;
    }

    public function handle(GetResponseEvent $event)
    {
        $token = $this->tokenStorage->getToken();
        $request = $event->getRequest();

        switch (true) {
            // The token is an instance of PreWebauthnToken and on the assertion path
            case $token instanceof PreWebauthnToken && $this->httpUtils->checkRequestPath($request, $this->options['assertion_check_path']) && Request::METHOD_POST === $request->getMethod():
                return $this->handleCheckAssertionPath($event, $token);
            // The token is an instance of PreWebauthnToken and not on the assertion path
            case $token instanceof PreWebauthnToken && !$this->httpUtils->checkRequestPath($request, $this->options['assertion_path']) && $token->getProviderKey() === $this->providerKey:
                $response = $this->httpUtils->createRedirectResponse($request, $this->options['assertion_path']);
                $event->setResponse($response);

                return;
            // The token is not a PreWebauthnToken and the page is the assertion page
            case !$token instanceof PreWebauthnToken && $this->httpUtils->checkRequestPath($request, $this->options['assertion_path']):
                $response = $this->httpUtils->createRedirectResponse($request, $this->options['login_path']);
                $event->setResponse($response);

                return;
            //The username has been submitted
            case $request->isMethod('POST') && $this->httpUtils->checkRequestPath($request, $this->options['login_check_path']):
                return $this->handleCheckUsernamePath($event);
            default:
                return;
        }
    }

    private function handleCheckAssertionPath(GetResponseEvent $event, PreWebauthnToken $token)
    {
        $request = $event->getRequest();
        Assertion::true($request->hasSession(), 'This authentication method requires a session.');
        try {
            /*if ($this->options['require_previous_session'] && !$request->hasPreviousSession()) {
                throw new SessionUnavailableException('Your session has timed out, or you have disabled cookies.');
            }*/
            $this->checkCsrfToken($request);
            $token = $this->processWithAssertion($request, $token);
            $authenticatedToken = $this->authenticationManager->authenticate($token);
            $this->sessionStrategy->onAuthentication($request, $authenticatedToken);
            $response = $this->onAssertionSuccess($request, $authenticatedToken);
        } catch (AuthenticationException $e) {
            dump('AuthenticationException $e');
            dump($e->getFile(), $e->getLine(), $e->getMessage());
            $response = $this->onAssertionFailure($request, $e);
        } catch (\Exception $e) {
            dump('\Exception $e');
            dump($e->getFile(), $e->getLine(), $e->getMessage(), $e->getPrevious());
            $response = $this->onAssertionFailure($request, new AuthenticationException($e->getMessage(), 0, $e));
        }

        $event->setResponse($response);
    }

    private function handleCheckUsernamePath(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        Assertion::true($request->hasSession(), 'This authentication method requires a session.');
        try {
            /*if ($this->options['require_previous_session'] && !$request->hasPreviousSession()) {
                throw new SessionUnavailableException('Your session has timed out, or you have disabled cookies.');
            }*/
            $this->checkCsrfToken($request);
            $token = $this->processWithUsername($request);
            $request->getSession()->set(Security::LAST_USERNAME, $token->getUsername());
            $authenticatedToken = $this->authenticationManager->authenticate($token);
            $this->sessionStrategy->onAuthentication($request, $authenticatedToken);
            $response = $this->onUsernameSuccess($request, $authenticatedToken);
        } catch (AuthenticationException $e) {
            $response = $this->onUsernameFailure($request, $e);
        } catch (\Exception $e) {
            $response = $this->onUsernameFailure($request, new AuthenticationException($e->getMessage(), 0, $e));
        }

        $event->setResponse($response);
    }

    private function checkCsrfToken(Request $request)
    {
        if (null !== $this->csrfTokenManager) {
            $csrfToken = $request->request->get($this->options['csrf_parameter']);
            if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['csrf_token_id'], $csrfToken))) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }
    }

    private function onUsernameFailure(Request $request, AuthenticationException $failed): Response
    {
        if (null !== $this->logger) {
            $this->logger->info('Webauthn pre-authentication request failed.', ['exception' => $failed]);
        }

        $token = $this->tokenStorage->getToken();
        if ($token instanceof PreWebauthnToken && $this->providerKey === $token->getProviderKey()) {
            $this->tokenStorage->setToken(null);
        }

        $session = $request->getSession();
        $session->set(Security::AUTHENTICATION_ERROR, $failed);

        return $this->httpUtils->createRedirectResponse($request, $this->options['login_path']);
    }

    private function onAssertionFailure(Request $request, AuthenticationException $failed): Response
    {
        if (null !== $this->logger) {
            $this->logger->info('Webauthn authentication request failed.', ['exception' => $failed]);
        }

        $token = $this->tokenStorage->getToken();
        if ($token instanceof WebauthnToken && $this->providerKey === $token->getProviderKey()) {
            $this->tokenStorage->setToken(null);
        }

        $session = $request->getSession();
        $session->set(Security::AUTHENTICATION_ERROR, $failed);

        return $this->httpUtils->createRedirectResponse($request, $this->options['assertion_path']);
    }

    /**
     * This function
     *  - logs the information message if asked.
     *  - sets the token
     *  - redirects to the assertion page.
     */
    private function onUsernameSuccess(Request $request, TokenInterface $token): Response
    {
        if (null !== $this->logger) {
            $this->logger->info('User has been pre-authenticated successfully.', ['username' => $token->getUsername()]);
        }

        $this->tokenStorage->setToken($token);

        $session = $request->getSession();
        $session->remove(Security::AUTHENTICATION_ERROR);
        $session->remove(Security::LAST_USERNAME);

        return $this->httpUtils->createRedirectResponse($request, $this->options['assertion_path']);

        /*if (null !== $this->dispatcher) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN, $loginEvent);
        }*/

        //$response = $this->successHandler->onAuthenticationSuccess($request, $token);
        /*if (null !== $this->rememberMeServices) {
            $this->rememberMeServices->loginSuccess($request, $response, $token);
        }*/
    }

    /**
     * This function
     *  - logs the information message if asked.
     *  - sets the token
     *  - redirects to the assertion page.
     */
    private function onAssertionSuccess(Request $request, TokenInterface $token): Response
    {
        if (null !== $this->logger) {
            $this->logger->info('User has been authenticated successfully.', ['username' => $token->getUsername()]);
        }

        $this->tokenStorage->setToken($token);

        $session = $request->getSession();
        $session->remove(Security::AUTHENTICATION_ERROR);

        return $this->httpUtils->createRedirectResponse($request, '/');

        /*if (null !== $this->dispatcher) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN, $loginEvent);
        }*/

        //$response = $this->successHandler->onAuthenticationSuccess($request, $token);
        /*if (null !== $this->rememberMeServices) {
            $this->rememberMeServices->loginSuccess($request, $response, $token);
        }*/
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

    private function processWithAssertion(Request $request, PreWebauthnToken $token): WebauthnToken
    {
        $assertion = $request->request->get($this->options['assertion_parameter']);

        if (!\is_string($assertion)) {
            throw new BadRequestHttpException(sprintf('The key "%s" must be a string, "%s" given.', $this->options['assertion_parameter'], \gettype($assertion)));
        }

        $assertion = trim($assertion);
        $publicKeyCredential = $this->publicKeyCredentialLoader->load($assertion);
        $response = $publicKeyCredential->getResponse();
        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw new AuthenticationException('Invalid assertion');
        }

        $this->authenticatorAssertionResponseValidator->check(
            $publicKeyCredential->getRawId(),
            $response,
            $token->getCredentials(),
            (new DiactorosFactory())->createRequest($request)
        );

        $newToken = new WebauthnToken(
            $token->getUsername(),
            $token->getCredentials(),
            $publicKeyCredential->getPublicKeyCredentialDescriptor(),
            $this->providerKey,
            $this->getRoles($token->getUser(), $token)
        );
        $newToken->setUser($token->getUser());

        return $newToken;
    }

    private function getRoles(UserInterface $user, TokenInterface $token): array
    {
        $roles = $user->getRoles();

        foreach ($token->getRoles() as $role) {
            if ($role instanceof SwitchUserRole) {
                $roles[] = $role;

                break;
            }
        }

        return $roles;
    }
}
