<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Listener;

use Assert\Assertion;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

class RequestResultListener
{
    public function __construct(
        private HttpMessageFactoryInterface $httpMessageFactory,
        private WebauthnFirewallConfig $firewallConfig,
        private AuthenticationSuccessHandlerInterface $authenticationSuccessHandler,
        private AuthenticationFailureHandlerInterface $authenticationFailureHandler,
        private OptionsStorage $optionsStorage,
        private array $securedRelyingPartyIds,
        private PublicKeyCredentialUserEntityRepository $userEntityRepository,
        private PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator,
        private TokenStorageInterface $tokenStorage,
        private SessionAuthenticationStrategyInterface $sessionStrategy,
        private ?EventDispatcherInterface $dispatcher = null
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();
        if (! $this->firewallConfig->isAuthenticationEnabled()) {
            return;
        }
        if (! $this->firewallConfig->isAuthenticationResultPathRequest($request)) {
            return;
        }

        try {
            $token = $this->processWithAssertion($request);
            //$authenticatedToken = $this->authenticationManager->authenticate($token);
            //$this->sessionStrategy->onAuthentication($request, $authenticatedToken);
            $response = $this->onAssertionSuccess($request/*, $authenticatedToken*/);
        } catch (AuthenticationException $e) {
            $response = $this->onAssertionFailure($request, $e);
        } catch (Throwable $e) {
            $response = $this->onAssertionFailure($request, new AuthenticationException($e->getMessage(), 0, $e));
        }

        $event->setResponse($response);
    }

    private function onAssertionFailure(Request $request, AuthenticationException $failed): Response
    {
        $token = $this->tokenStorage->getToken();
        if ($token instanceof WebauthnToken && $this->firewallConfig->getFirewallName() === $token->getFirewallName()) {
            $this->tokenStorage->setToken(null);
        }

        return $this->authenticationFailureHandler->onAuthenticationFailure($request, $failed);
    }

    /**
     * This function
     *  - logs the information message if asked.
     *  - sets the token
     *  - redirects to the assertion page.
     */
    private function onAssertionSuccess(Request $request, TokenInterface $token): Response
    {
        $this->tokenStorage->setToken($token);

        if ($this->dispatcher !== null) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch($loginEvent);
        }

        return $this->authenticationSuccessHandler->onAuthenticationSuccess($request, $token);
    }

    private function processWithAssertion(Request $request): WebauthnToken
    {
        $storedData = $this->optionsStorage->get($request);
        $assertion = $request->getContent();
        Assertion::string($assertion, 'Invalid assertion');
        $assertion = trim($assertion);
        $publicKeyCredential = $this->publicKeyCredentialLoader->load($assertion);
        $response = $publicKeyCredential->getResponse();
        if (! $response instanceof AuthenticatorAssertionResponse) {
            throw new AuthenticationException('Invalid assertion');
        }

        $psr7Request = $this->httpMessageFactory->createRequest($request);

        try {
            $options = $storedData->getPublicKeyCredentialOptions();
            Assertion::isInstanceOf($options, PublicKeyCredentialRequestOptions::class, 'Invalid options');
            $userEntity = $storedData->getPublicKeyCredentialUserEntity();

            $publicKeyCredentialSource = $this->authenticatorAssertionResponseValidator->check(
                $publicKeyCredential->getRawId(),
                $response,
                $options,
                $psr7Request,
                $userEntity?->getId(),
                $this->securedRelyingPartyIds
            );
            $userEntity = $this->userEntityRepository->findOneByUserHandle($publicKeyCredentialSource->getUserHandle());
            Assertion::isInstanceOf(
                $userEntity,
                PublicKeyCredentialUserEntity::class,
                'Unable to find the associated user entity'
            );
        } catch (Throwable $throwable) {
            throw new AuthenticationException('Invalid assertion', 0, $throwable);
        }

        return new WebauthnToken(
            $userEntity,
            $options,
            $publicKeyCredentialSource->getPublicKeyCredentialDescriptor(),
            $response->getAuthenticatorData()
                ->isUserPresent(),
            $response->getAuthenticatorData()
                ->isUserVerified(),
            $response->getAuthenticatorData()
                ->getReservedForFutureUse1(),
            $response->getAuthenticatorData()
                ->getReservedForFutureUse2(),
            $response->getAuthenticatorData()
                ->getSignCount(),
            $response->getAuthenticatorData()
                ->getExtensions(),
            $this->firewallConfig->getFirewallName(),
            []
        );
    }
}
