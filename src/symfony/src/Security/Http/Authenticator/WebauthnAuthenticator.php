<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Http\Authenticator;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Exception\HttpNotImplementedException;
use Webauthn\Bundle\Exception\MissingFeatureException;
use Webauthn\Bundle\Exception\MissingUserEntityException;
use Webauthn\Bundle\Repository\CanRegisterUserEntity;
use Webauthn\Bundle\Repository\CanSaveCredentialSource;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Http\Authenticator\Passport\Credentials\WebauthnCredentials;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\InvalidDataException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class WebauthnAuthenticator implements AuthenticatorInterface, InteractiveAuthenticatorInterface, CanLogData
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
        private readonly PublicKeyCredentialSourceRepository|PublicKeyCredentialSourceRepositoryInterface $publicKeyCredentialSourceRepository,
        private readonly PublicKeyCredentialUserEntityRepositoryInterface $credentialUserEntityRepository,
        private readonly PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private readonly AuthenticatorAssertionResponseValidator $assertionResponseValidator,
        private readonly AuthenticatorAttestationResponseValidator $attestationResponseValidator
    ) {
        if (! $this->publicKeyCredentialSourceRepository instanceof PublicKeyCredentialSourceRepositoryInterface) {
            trigger_deprecation(
                'web-auth/webauthn-symfony-bundle',
                '4.6.0',
                sprintf(
                    'Since 4.6.0, the parameter "$publicKeyCredentialSourceRepository" expects an instance of "%s". Please implement that interface instead of "%s".',
                    PublicKeyCredentialSourceRepositoryInterface::class,
                    PublicKeyCredentialSourceRepository::class
                )
            );
        }
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
        $credentialsBadge instanceof WebauthnCredentials || throw InvalidDataException::create(
            $credentialsBadge,
            'Invalid credentials'
        );
        $userBadge = $passport->getBadge(UserBadge::class);
        $userBadge instanceof UserBadge || throw InvalidDataException::create($userBadge, 'Invalid user');
        /** @var AuthenticatorAttestationResponse|AuthenticatorAssertionResponse $response */
        $response = $credentialsBadge->getAuthenticatorResponse();
        if ($response instanceof AuthenticatorAssertionResponse) {
            $authData = $response->getAuthenticatorData();
        } else {
            $authData = $response->getAttestationObject()
                ->getAuthData();
        }
        $userEntity = $credentialsBadge->getPublicKeyCredentialUserEntity();
        $userEntity !== null || throw new MissingUserEntityException('The user entity is missing');
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
                ->getRoles(),
            $authData->isBackupEligible(),
            $authData->isBackedUp(),
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
            $format = method_exists(
                $request,
                'getContentTypeFormat'
            ) ? $request->getContentTypeFormat() : $request->getContentType();
            $format === 'json' || throw InvalidDataException::create($format, 'Only JSON content type allowed');
            $content = $request->getContent();
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
            $response = $publicKeyCredential->getResponse();
            $response instanceof AuthenticatorAssertionResponse || throw InvalidDataException::create(
                $response,
                'Invalid response'
            );
            $data = $this->optionsStorage->get($response->getClientDataJSON()->getChallenge());
            $publicKeyCredentialRequestOptions = $data->getPublicKeyCredentialOptions();
            $publicKeyCredentialRequestOptions instanceof PublicKeyCredentialRequestOptions || throw InvalidDataException::create(
                $publicKeyCredentialRequestOptions,
                'Invalid data'
            );
            $userEntity = $data->getPublicKeyCredentialUserEntity();

            $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId(
                $publicKeyCredential->getRawId()
            );
            $publicKeyCredentialSource !== null || throw AuthenticatorResponseVerificationException::create(
                'The credential ID is invalid.'
            );
            $publicKeyCredentialSource = $this->assertionResponseValidator->check(
                $publicKeyCredentialSource,
                $response,
                $publicKeyCredentialRequestOptions,
                $request->getHost(),
                $userEntity?->getId(),
                $this->securedRelyingPartyIds
            );
            if ($this->publicKeyCredentialSourceRepository instanceof CanSaveCredentialSource) {
                $this->publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);
            }
            $userEntity = $this->credentialUserEntityRepository->findOneByUserHandle(
                $publicKeyCredentialSource->getUserHandle()
            );
            $userEntity instanceof PublicKeyCredentialUserEntity || throw InvalidDataException::create(
                $userEntity,
                'Invalid user entity'
            );
            $credentials = new WebauthnCredentials(
                $response,
                $publicKeyCredentialRequestOptions,
                $userEntity,
                $publicKeyCredentialSource,
                $this->firewallConfig->getFirewallName()
            );
            $userBadge = new UserBadge($userEntity->getName(), $this->userProvider->loadUserByIdentifier(...));
            return new Passport($userBadge, $credentials, [new RememberMeBadge()]);
        } catch (Throwable $e) {
            throw new AuthenticationException($e->getMessage(), $e->getCode(), $e);
        }
    }

    private function processWithAttestation(Request $request): Passport
    {
        try {
            if (! $this->credentialUserEntityRepository instanceof CanRegisterUserEntity) {
                throw MissingFeatureException::create('Unable to register the user.');
            }
            if (! $this->publicKeyCredentialSourceRepository instanceof CanSaveCredentialSource) {
                throw MissingFeatureException::create('Unable to register the credential.');
            }
            $format = method_exists(
                $request,
                'getContentTypeFormat'
            ) ? $request->getContentTypeFormat() : $request->getContentType();
            $format === 'json' || throw InvalidDataException::create($format, 'Only JSON content type allowed');
            $content = $request->getContent();
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
            $response = $publicKeyCredential->getResponse();
            $response instanceof AuthenticatorAttestationResponse || throw InvalidDataException::create(
                $response,
                'Invalid response'
            );
            $storedData = $this->optionsStorage->get($response->getClientDataJSON()->getChallenge());
            $publicKeyCredentialCreationOptions = $storedData->getPublicKeyCredentialOptions();
            $publicKeyCredentialCreationOptions instanceof PublicKeyCredentialCreationOptions || throw InvalidDataException::create(
                $publicKeyCredentialCreationOptions,
                'Unable to find the public key credential creation options'
            );
            $userEntity = $storedData->getPublicKeyCredentialUserEntity();
            $userEntity !== null || throw InvalidDataException::create(
                $userEntity,
                'Unable to find the public key credential user entity'
            );
            $credentialSource = $this->attestationResponseValidator->check(
                $response,
                $publicKeyCredentialCreationOptions,
                $request->getHost(),
                $this->securedRelyingPartyIds
            );
            if ($this->credentialUserEntityRepository->findOneByUsername($userEntity->getName()) !== null) {
                throw InvalidDataException::create($userEntity, 'The username already exists');
            }
            if ($this->publicKeyCredentialSourceRepository->findOneByCredentialId(
                $credentialSource->getPublicKeyCredentialId()
            ) !== null) {
                throw InvalidDataException::create($credentialSource, 'The credentials already exists');
            }
            $this->credentialUserEntityRepository->saveUserEntity($userEntity);
            $this->publicKeyCredentialSourceRepository->saveCredentialSource($credentialSource);
            $credentials = new WebauthnCredentials(
                $response,
                $publicKeyCredentialCreationOptions,
                $userEntity,
                $credentialSource,
                $this->firewallConfig->getFirewallName()
            );
            $userBadge = new UserBadge($userEntity->getName(), $this->userProvider->loadUserByIdentifier(...));
            return new Passport($userBadge, $credentials, [new RememberMeBadge()]);
        } catch (Throwable $e) {
            if ($e instanceof MissingFeatureException) {
                throw new HttpNotImplementedException($e->getMessage(), $e);
            }
            throw new AuthenticationException($e->getMessage(), $e->getCode(), $e);
        }
    }
}
