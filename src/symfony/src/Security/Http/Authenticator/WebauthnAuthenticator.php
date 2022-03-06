<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Http\Authenticator;

use function assert;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnTokenInterface;
use Webauthn\Bundle\Security\Http\Authenticator\Passport\Credentials\WebauthnCredentials;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;

final class WebauthnAuthenticator implements AuthenticatorInterface, InteractiveAuthenticatorInterface
{
    private LoggerInterface $logger;

    public function __construct(
        private WebauthnFirewallConfig $firewallConfig,
        private UserProviderInterface $userProvider,
        private AuthenticationSuccessHandlerInterface $successHandler,
        private AuthenticationFailureHandlerInterface $failureHandler,
        private TokenStorageInterface $tokenStorage,
        private EventDispatcherInterface $eventDispatcher,
        ?LoggerInterface $logger = null
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function supports(Request $request): ?bool
    {
        if ($request->getMethod() !== Request::METHOD_POST) {
            return false;
        }
        if ($this->firewallConfig->isAuthenticationEnabled()) {
            return $this->firewallConfig->isAuthenticationResultPathRequest($request);
        }
        if ($this->firewallConfig->isRegistrationEnabled()) {
            return $this->firewallConfig->isRegistrationResultPathRequest($request);
        }

        return false;
    }

    public function authenticate(Request $request): Passport
    {
        $currentToken = $this->tokenStorage->getToken();
        if (! ($currentToken instanceof WebauthnTokenInterface)) {
            throw new AccessDeniedException('User is not in a Webauthn authentication process.');
        }

        $credentials = new WebauthnCredentials($currentToken);
        $userBadge = new UserBadge($currentToken->getUserIdentifier(), [$this->userProvider, 'loadUserByIdentifier']);

        return new Passport($userBadge, $credentials, []);
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $credentialsBadge = $passport->getBadge(WebauthnCredentials::class);
        assert($credentialsBadge instanceof WebauthnCredentials);

        return $credentialsBadge->getWebauthnToken();
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $this->logger->info('User has been authenticated successfully with Webauthn.', [
            'username' => UsernameHelper::getTokenUsername($token),
        ]);
        $this->dispatchWebauthnAuthenticationEvent(WebauthnAuthenticationEvents::SUCCESS, $request, $token);

        // When it's still a WebauthnTokenInterface, keep showing the auth form
        if ($token instanceof WebauthnTokenInterface) {
            $this->dispatchWebauthnAuthenticationEvent(WebauthnAuthenticationEvents::REQUIRE, $request, $token);

            return $this->authenticationRequiredHandler->onAuthenticationRequired($request, $token);
        }

        $this->dispatchWebauthnAuthenticationEvent(WebauthnAuthenticationEvents::COMPLETE, $request, $token);

        return $this->successHandler->onAuthenticationSuccess($request, $token);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $currentToken = $this->tokenStorage->getToken();
        assert($currentToken instanceof WebauthnTokenInterface);
        $this->logger->info('Webauthn authentication request failed.', [
            'exception' => $exception,
        ]);
        $this->dispatchWebauthnAuthenticationEvent(WebauthnAuthenticationEvents::FAILURE, $request, $currentToken);

        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }

    public function isInteractive(): bool
    {
        return true;
    }

    private function dispatchWebauthnAuthenticationEvent(
        string $eventType,
        Request $request,
        TokenInterface $token
    ): void {
        $event = new WebauthnAuthenticationEvent($request, $token);
        $this->eventDispatcher->dispatch($event, $eventType);
    }
}
