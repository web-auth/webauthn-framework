<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security\Firewall;

use Assert\Assertion;
use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use RuntimeException;
use function Safe\json_encode;
use function Safe\sprintf;
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
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Model\PublicKeyCredentialFakeUserEntity;
use Webauthn\Bundle\Provider\FakePublicKeyCredentialUserEntityProvider;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Storage\RequestOptionsStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

class WebauthnListener implements ListenerInterface
{
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
     * @var PublicKeyCredentialLoader
     */
    private $publicKeyCredentialLoader;

    /**
     * @var PublicKeyCredentialUserEntityRepository
     */
    private $userEntityRepository;

    /**
     * @var AuthenticatorAssertionResponseValidator
     */
    private $authenticatorAssertionResponseValidator;

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
     * @var PublicKeyCredentialRequestOptionsFactory
     */
    private $publicKeyCredentialRequestOptionsFactory;
    /**
     * @var ValidatorInterface
     */
    private $validator;

    /**
     * @var FakePublicKeyCredentialUserEntityProvider
     */
    private $fakePublicKeyCredentialUserEntityProvider;

    /**
     * @var AuthenticationSuccessHandlerInterface
     */
    private $authenticationSuccessHandler;

    /**
     * @var AuthenticationFailureHandlerInterface
     */
    private $authenticationFailureHandler;

    /**
     * @var RequestOptionsStorage
     */
    private $requestOptionsStorage;
    /**
     * @var RequestOptionsHandler
     */
    private $requestOptionsHandler;

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory, PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator, TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, ?FakePublicKeyCredentialUserEntityProvider $fakePublicKeyCredentialSourceRepository, string $providerKey, array $options, AuthenticationSuccessHandlerInterface $authenticationSuccessHandler, AuthenticationFailureHandlerInterface $authenticationFailureHandler, RequestOptionsHandler $requestOptionsHandler, RequestOptionsStorage $requestOptionsStorage, LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null)
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
        $this->tokenStorage = $tokenStorage;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->authenticatorAssertionResponseValidator = $authenticatorAssertionResponseValidator;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->userEntityRepository = $userEntityRepository;
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;
        $this->serializer = $serializer;
        $this->publicKeyCredentialRequestOptionsFactory = $publicKeyCredentialRequestOptionsFactory;
        $this->validator = $validator;
        $this->fakePublicKeyCredentialUserEntityProvider = $fakePublicKeyCredentialSourceRepository;
        $this->authenticationSuccessHandler = $authenticationSuccessHandler;
        $this->authenticationFailureHandler = $authenticationFailureHandler;
        $this->requestOptionsStorage = $requestOptionsStorage;
        $this->requestOptionsHandler = $requestOptionsHandler;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event): void
    {
        $request = $event->getRequest();
        if (!$request->isMethod(Request::METHOD_POST)) {
            return;
        }
        if (false === mb_strpos($request->getRequestFormat(), 'json')
            && false === mb_strpos($request->getContentType(), 'json')
        ) {
            return;
        }
        Assertion::true($request->hasSession(), 'This authentication method requires a session.');

        switch (true) {
            case $this->httpUtils->checkRequestPath($request, $this->options['login_path']):
                $this->onLoginPath($event);
                break;
            case $this->httpUtils->checkRequestPath($request, $this->options['options_path']):
                $this->onOptionsPath($event);
                break;
            default:
                return;
        }
    }

    private function onOptionsPath(GetResponseEvent $event): void
    {
        $request = $event->getRequest();
        try {
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $creationOptionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);
            $userEntity = $this->userEntityRepository->findOneByUsername($creationOptionsRequest->username);
            if (null === $userEntity) {
                if (null === $this->fakePublicKeyCredentialUserEntityProvider) {
                    throw new InvalidArgumentException('User not found');
                }
                $userEntity = $this->fakePublicKeyCredentialUserEntityProvider->getFakeUserEntityFor($creationOptionsRequest->username);
                $allowedCredentials = $userEntity->getCredentials();
            } else {
                $allowedCredentials = $this->getCredentials($userEntity);
            }
            $publicKeyCredentialRequestOptions = $this->publicKeyCredentialRequestOptionsFactory->create(
                $this->options['profile'],
                $allowedCredentials
            );
            $this->requestOptionsStorage->store($request, new StoredData($publicKeyCredentialRequestOptions, $userEntity));
            $response = $this->requestOptionsHandler->onRequestOptions($publicKeyCredentialRequestOptions, $userEntity);
        } catch (\Exception $e) {
            $response = $this->onAssertionFailure($request, new AuthenticationException($e->getMessage(), 0, $e));
        }

        $event->setResponse($response);
    }

    private function getServerPublicKeyCredentialRequestOptionsRequest(string $content): ServerPublicKeyCredentialRequestOptionsRequest
    {
        $data = $this->serializer->deserialize($content, ServerPublicKeyCredentialRequestOptionsRequest::class, 'json');
        Assertion::isInstanceOf($data, ServerPublicKeyCredentialRequestOptionsRequest::class, 'Invalid data');
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

    private function onLoginPath(GetResponseEvent $event): void
    {
        $request = $event->getRequest();
        try {
            /*if ($this->options['require_previous_session'] && !$request->hasPreviousSession()) {
                throw new SessionUnavailableException('Your session has timed out, or you have disabled cookies.');
            }*/
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
        if (null !== $this->logger) {
            $this->logger->info('Webauthn authentication request failed.', ['exception' => $failed]);
        }

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

        if (null !== $this->dispatcher) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN, $loginEvent);
        }

        $response = $this->authenticationSuccessHandler->onAuthenticationSuccess($request, $token);

        if (!$response instanceof Response) {
            throw new RuntimeException('Authentication Success Handler did not return a Response.');
        }

        return $response;
    }

    private function processWithAssertion(Request $request): WebauthnToken
    {
        $storedData = $this->requestOptionsStorage->get($request);

        if ($storedData->getPublicKeyCredentialUserEntity() instanceof PublicKeyCredentialFakeUserEntity) {
            throw new BadRequestHttpException('Invalid assertion');
        }

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
            $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId($publicKeyCredential->getRawId());
            Assertion::notNull($publicKeyCredentialSource, 'Invalid credential ID');

            $this->authenticatorAssertionResponseValidator->check(
                $publicKeyCredential->getRawId(),
                $response,
                $storedData->getPublicKeyCredentialRequestOptions(),
                $psr7Request,
                $storedData->getPublicKeyCredentialUserEntity()->getId()
            );
        } catch (Throwable $throwable) {
            if (null !== $this->logger) {
                $this->logger->error(sprintf(
                    'Invalid assertion: %s. Request was: %s. Reason is: %s (%s:%d)',
                    $assertion,
                    json_encode($storedData->getPublicKeyCredentialRequestOptions()),
                    $throwable->getMessage(),
                    $throwable->getFile(),
                    $throwable->getLine()
                ));
            }
            throw new AuthenticationException('Invalid assertion:', 0, $throwable);
        }

        $token = new WebauthnToken(
            $storedData->getPublicKeyCredentialUserEntity(),
            $storedData->getPublicKeyCredentialRequestOptions(),
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

        return $token;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getCredentials(PublicKeyCredentialUserEntity $userEntity): array
    {
        $credentialSources = $this->publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(function (PublicKeyCredentialSource $credential) {
            return $credential->getPublicKeyCredentialDescriptor();
        }, $credentialSources);
    }
}
