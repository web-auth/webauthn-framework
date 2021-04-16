<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security\Firewall;

use Assert\Assertion;
use function count;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

class RequestListener
{
    private LoggerInterface $logger;

    private string $providerKey;

    /*
     * @var string[]
     */
    public function __construct(private HttpMessageFactoryInterface $httpMessageFactory, private SerializerInterface $serializer, private ValidatorInterface $validator, private PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory, private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, private PublicKeyCredentialUserEntityRepository $userEntityRepository, private PublicKeyCredentialLoader $publicKeyCredentialLoader, private AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator, private TokenStorageInterface $tokenStorage, private AuthenticationManagerInterface $authenticationManager, private SessionAuthenticationStrategyInterface $sessionStrategy, string $providerKey, private array $options, private AuthenticationSuccessHandlerInterface $authenticationSuccessHandler, private AuthenticationFailureHandlerInterface $authenticationFailureHandler, private RequestOptionsHandler $optionsHandler, private OptionsStorage $optionsStorage, ?LoggerInterface $logger = null, private ?EventDispatcherInterface $dispatcher = null, private array $securedRelyingPartyId = [])
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');
        $this->providerKey = $providerKey;
        $this->logger = $logger ?? new NullLogger();
    }

    public function processWithRequestOptions(RequestEvent $event): void
    {
        $request = $event->getRequest();
        try {
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $creationOptionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);
            $extensions = null !== $creationOptionsRequest->extensions ? AuthenticationExtensionsClientInputs::createFromArray($creationOptionsRequest->extensions) : null;
            $userEntity = null === $creationOptionsRequest->username ? null : $this->userEntityRepository->findOneByUsername($creationOptionsRequest->username);
            $allowedCredentials = null !== $userEntity ? $this->getCredentials($userEntity) : [];
            $publicKeyCredentialRequestOptions = $this->publicKeyCredentialRequestOptionsFactory->create(
                $this->options['profile'],
                $allowedCredentials,
                $creationOptionsRequest->userVerification,
                $extensions
            );
            $response = $this->optionsHandler->onRequestOptions($publicKeyCredentialRequestOptions, $userEntity);
            $this->optionsStorage->store($request, new StoredData($publicKeyCredentialRequestOptions, $userEntity), $response);
        } catch (Throwable $e) {
            $this->logger->error('An error occurred', ['exception' => $e]);
            $response = $this->onAssertionFailure($request, new AuthenticationException($e->getMessage(), 0, $e));
        }

        $event->setResponse($response);
    }

    public function processWithRequestResult(RequestEvent $event): void
    {
        $request = $event->getRequest();
        try {
            $token = $this->processWithAssertion($request);
            $authenticatedToken = $this->authenticationManager->authenticate($token);
            $this->sessionStrategy->onAuthentication($request, $authenticatedToken);
            $response = $this->onAssertionSuccess($request, $authenticatedToken);
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
        if ($token instanceof WebauthnToken && $this->providerKey === $token->getProviderKey()) {
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

        if (null !== $this->dispatcher) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch($loginEvent);
        }

        return $this->authenticationSuccessHandler->onAuthenticationSuccess($request, $token);
    }

    private function getServerPublicKeyCredentialRequestOptionsRequest(string $content): ServerPublicKeyCredentialRequestOptionsRequest
    {
        $data = $this->serializer->deserialize(
            $content,
            ServerPublicKeyCredentialRequestOptionsRequest::class,
            'json',
            [AbstractObjectNormalizer::DISABLE_TYPE_ENFORCEMENT => true]
        );
        Assertion::isInstanceOf($data, ServerPublicKeyCredentialRequestOptionsRequest::class, 'Invalid data');
        $errors = $this->validator->validate($data);
        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath().': '.$error->getMessage();
            }
            throw new RuntimeException(implode("\n", $messages));
        }

        return $data;
    }

    private function processWithAssertion(Request $request): WebauthnToken
    {
        $storedData = $this->optionsStorage->get($request);
        $assertion = $request->getContent();
        Assertion::string($assertion, 'Invalid assertion');
        $assertion = trim($assertion);
        $publicKeyCredential = $this->publicKeyCredentialLoader->load($assertion);
        $response = $publicKeyCredential->getResponse();
        if (!$response instanceof AuthenticatorAssertionResponse) {
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
                null === $userEntity ? null : $userEntity->getId(),
                $this->securedRelyingPartyId
            );
            $userEntity = $this->userEntityRepository->findOneByUserHandle($publicKeyCredentialSource->getUserHandle());
            Assertion::isInstanceOf($userEntity, PublicKeyCredentialUserEntity::class, 'Unable to find the associated user entity');
        } catch (Throwable $throwable) {
            throw new AuthenticationException('Invalid assertion', 0, $throwable);
        }

        return new WebauthnToken(
            $userEntity,
            $options,
            $publicKeyCredentialSource->getPublicKeyCredentialDescriptor(),
            $response->getAuthenticatorData()->isUserPresent(),
            $response->getAuthenticatorData()->isUserVerified(),
            $response->getAuthenticatorData()->getReservedForFutureUse1(),
            $response->getAuthenticatorData()->getReservedForFutureUse2(),
            $response->getAuthenticatorData()->getSignCount(),
            $response->getAuthenticatorData()->getExtensions(),
            $this->providerKey,
            []
        );
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getCredentials(PublicKeyCredentialUserEntity $userEntity): array
    {
        $credentialSources = $this->publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
            return $credential->getPublicKeyCredentialDescriptor();
        }, $credentialSources);
    }
}
