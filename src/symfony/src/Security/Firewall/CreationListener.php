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
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Handler\CreationOptionsHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

class CreationListener
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var array<string, mixed>
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
     * @var SessionAuthenticationStrategyInterface
     */
    private $sessionStrategy;

    /**
     * @var EventDispatcherInterface
     */
    private $dispatcher;

    /**
     * @var PublicKeyCredentialLoader
     */
    private $publicKeyCredentialLoader;

    /**
     * @var PublicKeyCredentialUserEntityRepository
     */
    private $publicKeyUserEntityRepository;

    /**
     * @var AuthenticatorAttestationResponseValidator
     */
    private $authenticatorAttestationResponseValidator;

    /**
     * @var HttpMessageFactoryInterface
     */
    private $httpMessageFactory;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $publicKeyCredentialSourceRepository;

    /**
     * @var SerializerInterface
     */
    private $serializer;

    /**
     * @var PublicKeyCredentialCreationOptionsFactory
     */
    private $publicKeyCredentialCreationOptionsFactory;

    /**
     * @var ValidatorInterface
     */
    private $validator;

    /**
     * @var AuthenticationSuccessHandlerInterface
     */
    private $authenticationSuccessHandler;

    /**
     * @var AuthenticationFailureHandlerInterface
     */
    private $authenticationFailureHandler;

    /**
     * @var OptionsStorage
     */
    private $optionsStorage;

    /**
     * @var CreationOptionsHandler
     */
    private $optionsHandler;

    /**
     * @var string[]
     */
    private $securedRelyingPartyId;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory, PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAttestationResponseValidator $authenticatorAttestationResponseValidator, TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, string $providerKey, array $options, AuthenticationSuccessHandlerInterface $authenticationSuccessHandler, AuthenticationFailureHandlerInterface $authenticationFailureHandler, CreationOptionsHandler $optionsHandler, OptionsStorage $optionsStorage, ?LoggerInterface $logger = null, ?EventDispatcherInterface $dispatcher = null, array $securedRelyingPartyId = [])
    {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');

        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->sessionStrategy = $sessionStrategy;
        $this->providerKey = $providerKey;
        $this->options = $options;
        $this->logger = $logger ?? new NullLogger();
        $this->dispatcher = $dispatcher;
        $this->tokenStorage = $tokenStorage;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->authenticatorAttestationResponseValidator = $authenticatorAttestationResponseValidator;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->publicKeyUserEntityRepository = $userEntityRepository;
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;
        $this->serializer = $serializer;
        $this->publicKeyCredentialCreationOptionsFactory = $publicKeyCredentialCreationOptionsFactory;
        $this->validator = $validator;
        $this->authenticationSuccessHandler = $authenticationSuccessHandler;
        $this->authenticationFailureHandler = $authenticationFailureHandler;
        $this->optionsStorage = $optionsStorage;
        $this->optionsHandler = $optionsHandler;
        $this->securedRelyingPartyId = $securedRelyingPartyId;
    }

    public function processWithCreationOptions(RequestEvent $event): void
    {
        $request = $event->getRequest();
        try {
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $creationOptionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);
            $authenticatorSelection = null !== $creationOptionsRequest->authenticatorSelection ? AuthenticatorSelectionCriteria::createFromArray($creationOptionsRequest->authenticatorSelection) : null;
            $extensions = null !== $creationOptionsRequest->extensions ? AuthenticationExtensionsClientInputs::createFromArray($creationOptionsRequest->extensions) : null;
            $userEntity = $this->publicKeyUserEntityRepository->findOneByUsername($creationOptionsRequest->username);
            Assertion::null($userEntity, 'Invalid username');
            $userEntity = $this->publicKeyUserEntityRepository->createUserEntity(
                $creationOptionsRequest->username,
                $creationOptionsRequest->displayName,
                null
            );
            $publicKeyCredentialCreationOptions = $this->publicKeyCredentialCreationOptionsFactory->create(
                $this->options['profile'],
                $userEntity,
                [],
                $authenticatorSelection,
                $creationOptionsRequest->attestation,
                $extensions
            );
            $response = $this->optionsHandler->onCreationOptions($publicKeyCredentialCreationOptions, $userEntity);
            $this->optionsStorage->store($request, new StoredData($publicKeyCredentialCreationOptions, $userEntity), $response);
        } catch (\Exception $e) {
            $response = $this->onAssertionFailure($request, new AuthenticationException($e->getMessage(), 0, $e));
        }

        $event->setResponse($response);
    }

    public function processWithCreationResult(RequestEvent $event): void
    {
        $request = $event->getRequest();
        try {
            $token = $this->processWithAssertion($request);
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

    private function onAssertionFailure(Request $request, AuthenticationException $failed): Response
    {
        $token = $this->tokenStorage->getToken();
        if ($token instanceof WebauthnToken && $this->providerKey === $token->getProviderKey()) {
            $this->tokenStorage->setToken(null);
        }

        $response = $this->authenticationFailureHandler->onAuthenticationFailure($request, $failed);

        if (!$response instanceof Response) {
            throw new RuntimeException('Authentication Failure Handler did not return a Response.');
        }

        return $response;
    }

    private function onAssertionSuccess(Request $request, TokenInterface $token): Response
    {
        $this->tokenStorage->setToken($token);

        if (null !== $this->dispatcher) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch($loginEvent);
        }

        $response = $this->authenticationSuccessHandler->onAuthenticationSuccess($request, $token);

        if (!$response instanceof Response) {
            throw new RuntimeException('Authentication Success Handler did not return a Response.');
        }

        return $response;
    }

    private function getServerPublicKeyCredentialCreationOptionsRequest(string $content): ServerPublicKeyCredentialCreationOptionsRequest
    {
        $data = $this->serializer->deserialize($content, ServerPublicKeyCredentialCreationOptionsRequest::class, 'json');
        Assertion::isInstanceOf($data, ServerPublicKeyCredentialCreationOptionsRequest::class, 'Invalid data');
        $errors = $this->validator->validate($data);
        if (\count($errors) > 0) {
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
        if (!$response instanceof AuthenticatorAttestationResponse) {
            throw new AuthenticationException('Invalid assertion');
        }

        $psr7Request = $this->httpMessageFactory->createRequest($request);

        try {
            $options = $storedData->getPublicKeyCredentialOptions();
            Assertion::isInstanceOf($options, PublicKeyCredentialCreationOptions::class, 'Invalid options');
            $userEntity = $storedData->getPublicKeyCredentialUserEntity();
            Assertion::notNull($userEntity, 'Invalid user entity');

            $publicKeyCredentialSource = $this->authenticatorAttestationResponseValidator->check(
                $response,
                $options,
                $psr7Request,
                $this->securedRelyingPartyId
            );

            $this->publicKeyUserEntityRepository->saveUserEntity($userEntity);
            $this->publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);
        } catch (Throwable $throwable) {
            throw new AuthenticationException('Invalid assertion', 0, $throwable);
        }

        $token = new WebauthnToken(
            $userEntity,
            $options,
            $publicKeyCredentialSource->getPublicKeyCredentialDescriptor(),
            $response->getAttestationObject()->getAuthData()->isUserPresent(),
            $response->getAttestationObject()->getAuthData()->isUserVerified(),
            $response->getAttestationObject()->getAuthData()->getReservedForFutureUse1(),
            $response->getAttestationObject()->getAuthData()->getReservedForFutureUse2(),
            $response->getAttestationObject()->getAuthData()->getSignCount(),
            $response->getAttestationObject()->getAuthData()->getExtensions(),
            $this->providerKey,
            []
        );

        return $token;
    }
}
