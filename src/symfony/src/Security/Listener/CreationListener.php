<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Listener;

use Assert\Assertion;
use function count;
use Exception;
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
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Authentication\Token\WebauthnToken;
use Webauthn\Bundle\Security\Handler\CreationOptionsHandler;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

class CreationListener
{
    private LoggerInterface $logger;

    private string $providerKey;

    /**
     * @param mixed[] $options
     */
    public function __construct(
        private HttpMessageFactoryInterface $httpMessageFactory,
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        private PublicKeyCredentialUserEntityRepository $publicKeyUserEntityRepository,
        private PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private AuthenticatorAttestationResponseValidator $authenticatorAttestationResponseValidator,
        private TokenStorageInterface $tokenStorage,
        private AuthenticationManagerInterface $authenticationManager,
        private SessionAuthenticationStrategyInterface $sessionStrategy,
        string $providerKey,
        private array $options,
        private AuthenticationSuccessHandlerInterface $authenticationSuccessHandler,
        private AuthenticationFailureHandlerInterface $authenticationFailureHandler,
        private CreationOptionsHandler $optionsHandler,
        private OptionsStorage $optionsStorage,
        ?LoggerInterface $logger = null,
        private ?EventDispatcherInterface $dispatcher = null,
        private array $securedRelyingPartyId = []
    ) {
        Assertion::notEmpty($providerKey, '$providerKey must not be empty.');
        $this->providerKey = $providerKey;
        $this->logger = $logger ?? new NullLogger();
        $this->tokenStorage = $tokenStorage;
    }

    public function processWithCreationOptions(RequestEvent $event): void
    {
        $request = $event->getRequest();
        try {
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $creationOptionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);
            $authenticatorSelection = $creationOptionsRequest->authenticatorSelection !== null ? AuthenticatorSelectionCriteria::createFromArray(
                $creationOptionsRequest->authenticatorSelection
            ) : null;
            $extensions = $creationOptionsRequest->extensions !== null ? AuthenticationExtensionsClientInputs::createFromArray(
                $creationOptionsRequest->extensions
            ) : null;
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
            $this->optionsStorage->store(Item::create($publicKeyCredentialCreationOptions, $userEntity),);
        } catch (Exception $e) {
            $this->logger->error('Unable to process the creation option request');
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
        } catch (Exception $e) {
            $response = $this->onAssertionFailure($request, new AuthenticationException($e->getMessage(), 0, $e));
        }

        $event->setResponse($response);
    }

    private function onAssertionFailure(Request $request, AuthenticationException $failed): Response
    {
        $token = $this->tokenStorage->getToken();
        if ($token instanceof WebauthnToken && $this->providerKey === $token->getFirewallName()) {
            $this->tokenStorage->setToken(null);
        }

        return $this->authenticationFailureHandler->onAuthenticationFailure($request, $failed);
    }

    private function onAssertionSuccess(Request $request, TokenInterface $token): Response
    {
        $this->tokenStorage->setToken($token);

        if ($this->dispatcher !== null) {
            $loginEvent = new InteractiveLoginEvent($request, $token);
            $this->dispatcher->dispatch($loginEvent);
        }

        return $this->authenticationSuccessHandler->onAuthenticationSuccess($request, $token);
    }

    private function getServerPublicKeyCredentialCreationOptionsRequest(
        string $content
    ): ServerPublicKeyCredentialCreationOptionsRequest {
        $data = $this->serializer->deserialize(
            $content,
            ServerPublicKeyCredentialCreationOptionsRequest::class,
            'json',
            [
                AbstractObjectNormalizer::DISABLE_TYPE_ENFORCEMENT => true,
            ]
        );
        Assertion::isInstanceOf($data, ServerPublicKeyCredentialCreationOptionsRequest::class, 'Invalid data');
        $errors = $this->validator->validate($data);
        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            throw new RuntimeException(implode("\n", $messages));
        }

        return $data;
    }

    private function processWithAssertion(Request $request): WebauthnToken
    {
        $storedData = $this->optionsStorage->get();
        $assertion = $request->getContent();
        Assertion::string($assertion, 'Invalid assertion');
        $assertion = trim($assertion);
        $publicKeyCredential = $this->publicKeyCredentialLoader->load($assertion);
        $response = $publicKeyCredential->getResponse();
        if (! $response instanceof AuthenticatorAttestationResponse) {
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

        return new WebauthnToken(
            $userEntity,
            $options,
            $publicKeyCredentialSource->getPublicKeyCredentialDescriptor(),
            $response->getAttestationObject()
                ->getAuthData()
                ->isUserPresent(),
            $response->getAttestationObject()
                ->getAuthData()
                ->isUserVerified(),
            $response->getAttestationObject()
                ->getAuthData()
                ->getReservedForFutureUse1(),
            $response->getAttestationObject()
                ->getAuthData()
                ->getReservedForFutureUse2(),
            $response->getAttestationObject()
                ->getAuthData()
                ->getSignCount(),
            $response->getAttestationObject()
                ->getAuthData()
                ->getExtensions(),
            $this->providerKey,
            []
        );
    }
}
