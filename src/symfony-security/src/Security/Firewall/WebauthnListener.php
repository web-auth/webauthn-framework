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

namespace Webauthn\SecurityBundle\Security\Firewall;

use Assert\Assertion;
use Psr\Log\LoggerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
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
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\SecurityBundle\Model\CanHaveRegisteredSecurityDevices;
use Webauthn\SecurityBundle\Model\HasUserHandle;
use Webauthn\SecurityBundle\Security\Authentication\Token\PreWebauthnToken;
use Webauthn\SecurityBundle\Security\Authentication\Token\WebauthnToken;

class WebauthnListener implements ListenerInterface
{
    /**
     * @var CsrfTokenManagerInterface
     */
    private $csrfTokenManager;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var array
     */
    private $options;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var AuthenticationManagerInterface
     */
    private $authenticationManager;

    /**
     * @var string
     */
    private $providerKey;

    /**
     * @var HttpUtils
     */
    private $httpUtils;

    /**
     * @var SessionAuthenticationStrategyInterface
     */
    private $sessionStrategy;

    /**
     * @var EventDispatcherInterface
     */
    private $dispatcher;

    /**
     * @var RememberMeServicesInterface
     */
    private $rememberMeServices;

    /**
     * @var PublicKeyCredentialLoader
     */
    private $publicKeyCredentialLoader;

    /**
     * @var AuthenticatorAssertionResponseValidator
     */
    private $authenticatorAssertionResponseValidator;

    /**
     * @var HttpMessageFactoryInterface
     */
    private $httpMessageFactory;

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator, TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, string $providerKey, array $options = [], LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CsrfTokenManagerInterface $csrfTokenManager = null)
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
        $this->httpMessageFactory = $httpMessageFactory;
    }

    public function setRememberMeServices(RememberMeServicesInterface $rememberMeServices): void
    {
        $this->rememberMeServices = $rememberMeServices;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event): void
    {
        $token = $this->tokenStorage->getToken();
        $request = $event->getRequest();

        switch (true) {
            // Cancel the process
            case $this->httpUtils->checkRequestPath($request, $this->options['abort_path']):
                if ($token instanceof PreWebauthnToken && $this->providerKey === $token->getProviderKey()) {
                    $this->tokenStorage->setToken(null);
                }
                $response = $this->httpUtils->createRedirectResponse($request, $this->options['login_path']);
                $event->setResponse($response);

                return;
            // The token is an instance of PreWebauthnToken and on the assertion path
            case $request->isMethod(Request::METHOD_POST) && $token instanceof PreWebauthnToken && $this->httpUtils->checkRequestPath($request, $this->options['assertion_check_path']):
                $this->handleCheckAssertionPath($event, $token);

                return;
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
            case $request->isMethod(Request::METHOD_POST) && $this->httpUtils->checkRequestPath($request, $this->options['login_check_path']):
                $this->handleCheckUsernamePath($event);

                return;
            default:
                return;
        }
    }

    private function handleCheckAssertionPath(GetResponseEvent $event, PreWebauthnToken $token): void
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
            $response = $this->onAssertionFailure($request, $e);
        } catch (\Exception $e) {
            $response = $this->onAssertionFailure($request, new AuthenticationException($e->getMessage(), 0, $e));
        }

        $event->setResponse($response);
    }

    private function handleCheckUsernamePath(GetResponseEvent $event): void
    {
        $request = $event->getRequest();
        Assertion::true($request->hasSession(), 'This authentication method requires a session.');
        try {
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

    private function checkCsrfToken(Request $request): void
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

        if (null !== $this->dispatcher) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN, $loginEvent);
        }

        $response = $this->httpUtils->createRedirectResponse($request, '/');
        if (null !== $this->rememberMeServices) {
            $this->rememberMeServices->loginSuccess($request, $response, $token);
        }

        return $response;
    }

    private function processWithUsername(Request $request): PreWebauthnToken
    {
        $username = $request->request->get($this->options['username_parameter']);
        $rememberMe = $this->isRememberMeRequested($request);

        if (!\is_string($username)) {
            throw new BadRequestHttpException(\Safe\sprintf('The key "%s" must be a string, "%s" given.', $this->options['username_parameter'], \gettype($username)));
        }

        $username = trim($username);

        if (\mb_strlen($username) > Security::MAX_USERNAME_LENGTH) {
            throw new BadCredentialsException('Invalid username.');
        }

        $request->getSession()->set(Security::LAST_USERNAME, $username);

        return new PreWebauthnToken($username, $this->providerKey, $rememberMe);
    }

    private function processWithAssertion(Request $request, PreWebauthnToken $token): WebauthnToken
    {
        $assertion = $request->request->get($this->options['assertion_parameter']);
        $PublicKeyCredentialRequestOptions = $request->getSession()->get($this->options['assertion_session_parameter']);

        if (!$PublicKeyCredentialRequestOptions instanceof PublicKeyCredentialRequestOptions) {
            throw new BadRequestHttpException('No public key credential request options available for this session.');
        }
        if (!\is_string($assertion)) {
            throw new BadRequestHttpException(\Safe\sprintf('The key "%s" must be a string, "%s" given.', $this->options['assertion_parameter'], \gettype($assertion)));
        }

        $assertion = trim($assertion);
        $publicKeyCredential = $this->publicKeyCredentialLoader->load($assertion);
        $response = $publicKeyCredential->getResponse();
        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw new AuthenticationException('Invalid assertion');
        }

        $psr7Request = $this->httpMessageFactory->createRequest($request);

        try {
            $user = $token->getUser();
            Assertion::isInstanceOf($user, CanHaveRegisteredSecurityDevices::class, 'Invalid user class');

            $this->authenticatorAssertionResponseValidator->check(
                $publicKeyCredential->getRawId(),
                $response,
                $PublicKeyCredentialRequestOptions,
                $psr7Request,
                $user instanceof HasUserHandle ? $user->getUserHandle() : null
            );
        } catch (\Throwable $throwable) {
            if (null !== $this->logger) {
                $this->logger->error(\Safe\sprintf(
                    'Invalid assertion: %s. Request was: %s. Reason is: %s (%s:%d)',
                    $assertion,
                    \Safe\json_encode($PublicKeyCredentialRequestOptions),
                    $throwable->getMessage(),
                    $throwable->getFile(),
                    $throwable->getLine()
                ));
            }
            throw new AuthenticationException('Invalid assertion', 0, $throwable);
        }

        $newToken = new WebauthnToken(
            $token->getUsername(),
            $PublicKeyCredentialRequestOptions,
            $publicKeyCredential->getPublicKeyCredentialDescriptor(),
            $response->getAuthenticatorData()->isUserPresent(),
            $response->getAuthenticatorData()->isUserVerified(),
            $response->getAuthenticatorData()->getReservedForFutureUse1(),
            $response->getAuthenticatorData()->getReservedForFutureUse2(),
            $response->getAuthenticatorData()->getSignCount(),
            $response->getAuthenticatorData()->getExtensions(),
            $this->providerKey,
            $this->getRoles($token)
        );
        $newToken->setUser($token->getUser());

        return $newToken;
    }

    private function getRoles(TokenInterface $token): array
    {
        $user = $token->getUser();
        $roles = $user instanceof UserInterface ? $user->getRoles() : [];

        foreach ($token->getRoles() as $role) {
            if ($role instanceof SwitchUserRole) {
                $roles[] = $role;

                break;
            }
        }

        return $roles;
    }

    private function isRememberMeRequested(Request $request): bool
    {
        if (null === $this->options['remember_me_parameter']) {
            return false;
        }

        $parameter = $request->request->get($this->options['remember_me_parameter']);

        if (null === $parameter && null !== $this->logger) {
            $this->logger->debug('Did not send remember-me cookie.', ['parameter' => $this->options['remember_me_parameter']]);
        }

        return 'true' === $parameter || 'on' === $parameter || '1' === $parameter || 'yes' === $parameter || true === $parameter;
    }
}
