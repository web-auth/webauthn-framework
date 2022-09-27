<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Http\Authenticator;

use InvalidArgumentException;
use function is_string;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Http\Authenticator\Passport\Credentials\WebauthnCredentials;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class WebauthnAuthenticator implements AuthenticatorInterface, InteractiveAuthenticatorInterface
{
    private LoggerInterface $logger;

    /**
     * @param string[] $securedRelyingPartyIds
     */
    public function __construct(
        private readonly WebauthnFirewallConfig $firewallConfig,
        private readonly UserProviderInterface $userProvider,
        private readonly AuthenticationSuccessHandlerInterface $successHandler,
        private readonly AuthenticationFailureHandlerInterface $failureHandler,
        private readonly OptionsStorage $optionsStorage,
        private readonly array $securedRelyingPartyIds,
        private readonly HttpMessageFactoryInterface $httpMessageFactory,
        private readonly PublicKeyCredentialSourceRepository $credentialSourceRepository,
        private readonly PublicKeyCredentialUserEntityRepository $credentialUserEntityRepository,
        private readonly PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private readonly AuthenticatorAssertionResponseValidator $assertionResponseValidator,
        private readonly AuthenticatorAttestationResponseValidator $attestationResponseValidator
    ) {
        $this->logger = new NullLogger();
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function supports(Request $request): ?bool
    {
        if ($request->getMethod() !== Request::METHOD_POST) {
            return false;
        }

        if ($this->firewallConfig->isAuthenticationEnabled() && $this->firewallConfig->isAuthenticationResultPathRequest(
            $request
        )) {
            return true;
        }
        if ($this->firewallConfig->isRegistrationEnabled() && $this->firewallConfig->isRegistrationResultPathRequest(
            $request
        )) {
            return true;
        }

        return false;
    }

    public function authenticate(Request $request): Passport
    {
        if ($this->firewallConfig->isAuthenticationResultPathRequest($request)) {
            return $this->processWithAssertion($request);
        }

        return $this->processWithAttestation($request);
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $credentialsBadge = $passport->getBadge(WebauthnCredentials::class);
        $credentialsBadge instanceof WebauthnCredentials || throw new InvalidArgumentException('Invalid credentials');

        $userBadge = $passport->getBadge(UserBadge::class);
        $userBadge instanceof UserBadge || throw new InvalidArgumentException('Invalid user');

        /** @var AuthenticatorAttestationResponse|AuthenticatorAssertionResponse $response */
        $response = $credentialsBadge->getAuthenticatorResponse();
        if ($response instanceof AuthenticatorAssertionResponse) {
            $authData = $response->getAuthenticatorData();
        } else {
            $authData = $response->getAttestationObject()
                ->getAuthData();
        }
        $userEntity = $credentialsBadge->getPublicKeyCredentialUserEntity();
        $userEntity !== null || throw new InvalidArgumentException('The user entity is missing');

        $token = new WebauthnToken(
            $userEntity,
            $credentialsBadge->getPublicKeyCredentialOptions(),
            $credentialsBadge->getPublicKeyCredentialSource()
                ->getPublicKeyCredentialDescriptor(),
            $authData->isUserPresent(),
            $authData->isUserVerified(),
            $authData->getReservedForFutureUse1(),
            $authData->getReservedForFutureUse2(),
            $authData->getSignCount(),
            $authData->getExtensions(),
            $credentialsBadge->getFirewallName(),
            $userBadge->getUser()
                ->getRoles()
        );
        $token->setUser($userBadge->getUser());

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $this->logger->info('User has been authenticated successfully with Webauthn.', [
            'request' => $request,
            'firewallName' => $firewallName,
            'identifier' => $token->getUserIdentifier(),
        ]);

        return $this->successHandler->onAuthenticationSuccess($request, $token);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $this->logger->info('Webauthn authentication request failed.', [
            'request' => $request,
            'exception' => $exception,
        ]);

        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }

    public function isInteractive(): bool
    {
        return true;
    }

    private function processWithAssertion(Request $request): Passport
    {
        try {
            $request->getContentType() === 'json' || throw new InvalidArgumentException(
                'Only JSON content type allowed'
            );
            $content = $request->getContent();
            is_string($content) || throw new InvalidArgumentException('Invalid data');
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
            $response = $publicKeyCredential->getResponse();
            $response instanceof AuthenticatorAssertionResponse || throw new InvalidArgumentException(
                'Invalid response'
            );

            $data = $this->optionsStorage->get($response->getClientDataJSON()->getChallenge());
            $publicKeyCredentialRequestOptions = $data->getPublicKeyCredentialOptions();
            $publicKeyCredentialRequestOptions instanceof PublicKeyCredentialRequestOptions || throw new InvalidArgumentException(
                'Invalid data'
            );

            $userEntity = $data->getPublicKeyCredentialUserEntity();
            $psr7Request = $this->httpMessageFactory->createRequest($request);
            $source = $this->assertionResponseValidator->check(
                $publicKeyCredential->getRawId(),
                $response,
                $publicKeyCredentialRequestOptions,
                $psr7Request,
                $userEntity?->getId(),
                $this->securedRelyingPartyIds
            );

            $userEntity = $this->credentialUserEntityRepository->findOneByUserHandle($source->getUserHandle());
            $userEntity instanceof PublicKeyCredentialUserEntity || throw new InvalidArgumentException(
                'Invalid user entity'
            );

            $credentials = new WebauthnCredentials(
                $response,
                $publicKeyCredentialRequestOptions,
                $userEntity,
                $source,
                $this->firewallConfig->getFirewallName()
            );
            $userBadge = new UserBadge($userEntity->getName(), $this->userProvider->loadUserByIdentifier(...));

            return new Passport($userBadge, $credentials, []);
        } catch (Throwable $e) {
            throw new AuthenticationException($e->getMessage(), $e->getCode(), $e);
        }
    }

    private function processWithAttestation(Request $request): Passport
    {
        try {
            $request->getContentType() === 'json' || throw new InvalidArgumentException(
                'Only JSON content type allowed'
            );
            $content = $request->getContent();
            is_string($content) || throw new InvalidArgumentException('Invalid data');
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
            $response = $publicKeyCredential->getResponse();
            $response instanceof AuthenticatorAttestationResponse || throw new InvalidArgumentException(
                'Invalid response'
            );

            $storedData = $this->optionsStorage->get($response->getClientDataJSON()->getChallenge());
            $publicKeyCredentialCreationOptions = $storedData->getPublicKeyCredentialOptions();
            $publicKeyCredentialCreationOptions instanceof PublicKeyCredentialCreationOptions || throw new InvalidArgumentException(
                'Unable to find the public key credential creation options'
            );
            $userEntity = $storedData->getPublicKeyCredentialUserEntity();
            $userEntity !== null || throw new InvalidArgumentException(
                'Unable to find the public key credential user entity'
            );

            $psr7Request = $this->httpMessageFactory->createRequest($request);
            $credentialSource = $this->attestationResponseValidator->check(
                $response,
                $publicKeyCredentialCreationOptions,
                $psr7Request,
                $this->securedRelyingPartyIds
            );
            if ($this->credentialUserEntityRepository->findOneByUsername($userEntity->getName()) !== null) {
                throw new InvalidArgumentException('The username already exists');
            }
            if ($this->credentialSourceRepository->findOneByCredentialId(
                $credentialSource->getPublicKeyCredentialId()
            ) !== null) {
                throw new InvalidArgumentException('The credentials already exists');
            }
            $this->credentialUserEntityRepository->saveUserEntity($userEntity);
            $this->credentialSourceRepository->saveCredentialSource($credentialSource);

            $credentials = new WebauthnCredentials(
                $response,
                $publicKeyCredentialCreationOptions,
                $userEntity,
                $credentialSource,
                $this->firewallConfig->getFirewallName()
            );
            $userBadge = new UserBadge($userEntity->getName(), $this->userProvider->loadUserByIdentifier(...));

            return new Passport($userBadge, $credentials, []);
        } catch (Throwable $e) {
            throw new AuthenticationException($e->getMessage(), $e->getCode(), $e);
        }
    }
}
