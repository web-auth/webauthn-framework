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

namespace Webauthn\Bundle\Controller;

use Assert\Assertion;
use function Safe\sprintf;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Event\PublicKeyCredentialSourceRegistrationCompleted;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Handler\CreationFailureHandler;
use Webauthn\Bundle\Security\Handler\CreationSuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;

final class AttestationResponseController
{
    /**
     * @var PublicKeyCredentialUserEntityRepository
     */
    private $userEntityRepository;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $credentialSourceRepository;

    /**
     * @var PublicKeyCredentialLoader
     */
    private $publicKeyCredentialLoader;

    /**
     * @var AuthenticatorAttestationResponseValidator
     */
    private $attestationResponseValidator;

    /**
     * @var HttpMessageFactoryInterface
     */
    private $httpMessageFactory;

    /**
     * @var OptionsStorage
     */
    private $optionsStorage;

    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @var CreationFailureHandler
     */
    private $creationFailureHandler;

    /**
     * @var CreationSuccessHandler
     */
    private $creationSuccessHandler;
    /**
     * @var string
     */
    private $providerKey;
    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    public function __construct(string $providerKey, UserProviderInterface $userProvider, HttpMessageFactoryInterface $httpMessageFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAttestationResponseValidator $attestationResponseValidator, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository, OptionsStorage $optionsStorage, EventDispatcherInterface $eventDispatcher, CreationSuccessHandler $creationSuccessHandler, CreationFailureHandler $creationFailureHandler)
    {
        $this->providerKey = $providerKey;
        $this->userProvider = $userProvider;
        $this->attestationResponseValidator = $attestationResponseValidator;
        $this->userEntityRepository = $userEntityRepository;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->optionsStorage = $optionsStorage;
        $this->eventDispatcher = $eventDispatcher;
        $this->creationFailureHandler = $creationFailureHandler;
        $this->creationSuccessHandler = $creationSuccessHandler;
    }

    public function __invoke(Request $request): Response
    {
        try {
            $psr7Request = $this->httpMessageFactory->createRequest($request);
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
            $response = $publicKeyCredential->getResponse();
            Assertion::isInstanceOf($response, AuthenticatorAttestationResponse::class, 'Invalid response');
            $storedData = $this->optionsStorage->get($request);
            $publicKeyCredentialCreationOptions = $storedData->getPublicKeyCredentialOptions();
            $userEntity = $storedData->getPublicKeyCredentialUserEntity();
            Assertion::isInstanceOf($publicKeyCredentialCreationOptions, PublicKeyCredentialCreationOptions::class, 'Unable to find the public key credential creation options');
            $this->attestationResponseValidator->check($response, $publicKeyCredentialCreationOptions, $psr7Request);
            try {
                $user = $this->userProvider->loadUserByUsername($userEntity->getName());
            } catch (Throwable $throwable) {
                $user = null;
            }
            if (null !== $user) {
                throw new \LogicException(sprintf('User with username "%s" already exist', $user->getUsername()));
            }
            $this->userEntityRepository->saveUserEntity($userEntity);
            $credentialSource = PublicKeyCredentialSource::createFromPublicKeyCredential(
                $publicKeyCredential,
                $userEntity->getId()
            );
            $this->credentialSourceRepository->saveCredentialSource($credentialSource);
            $this->eventDispatcher->dispatch(new PublicKeyCredentialSourceRegistrationCompleted($this->providerKey, $publicKeyCredentialCreationOptions, $response, $credentialSource));

            return $this->creationSuccessHandler->onCreationSuccess($request, $publicKeyCredentialCreationOptions, $response, $credentialSource);
        } catch (Throwable $throwable) {
            return $this->creationFailureHandler->onCreationFailure($request, $throwable);
        }
    }
}
