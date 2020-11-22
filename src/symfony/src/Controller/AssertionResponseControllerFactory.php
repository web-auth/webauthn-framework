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

namespace Webauthn\Bundle\Controller;

use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\SuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

final class AssertionResponseControllerFactory
{
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
     * @var PublicKeyCredentialLoader
     */
    private $publicKeyCredentialLoader;

    /**
     * @var AuthenticatorAssertionResponseValidator
     */
    private $assertionResponseValidator;

    /**
     * @var HttpMessageFactoryInterface
     */
    private $httpMessageFactory;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $publicKeyCredentialSourceRepository;

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAssertionResponseValidator $assertionResponseValidator, PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository)
    {
        $this->serializer = $serializer;
        $this->validator = $validator;
        $this->publicKeyCredentialRequestOptionsFactory = $publicKeyCredentialRequestOptionsFactory;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->assertionResponseValidator = $assertionResponseValidator;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;
    }

    public function createAssertionRequestController(UserEntityGuesser $userEntityGuesser, string $profile, OptionsStorage $optionStorage, RequestOptionsHandler $creationOptionsHandler, FailureHandler $failureHandler): AssertionRequestController
    {
        return new AssertionRequestController(
            $userEntityGuesser,
            $this->serializer,
            $this->validator,
            $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialRequestOptionsFactory,
            $profile,
            $optionStorage,
            $creationOptionsHandler,
            $failureHandler
        );
    }

    public function createAssertionResponseController(OptionsStorage $optionStorage, SuccessHandler $successHandler, FailureHandler $failureHandler): AssertionResponseController
    {
        return new AssertionResponseController(
            $this->httpMessageFactory,
            $this->publicKeyCredentialLoader,
            $this->assertionResponseValidator,
            $this->publicKeyCredentialSourceRepository,
            $optionStorage,
            $successHandler,
            $failureHandler
        );
    }
}
