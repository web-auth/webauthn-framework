<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Controller;

use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
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
     * @var AuthenticatorAssertionResponseValidator
     */
    private $attestationResponseValidator;

    public function __construct(SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository, PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAssertionResponseValidator $attestationResponseValidator)
    {
        $this->serializer = $serializer;
        $this->validator = $validator;
        $this->publicKeyCredentialRequestOptionsFactory = $publicKeyCredentialRequestOptionsFactory;
        $this->userEntityRepository = $userEntityRepository;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->attestationResponseValidator = $attestationResponseValidator;
    }

    public function createAssertionRequestController(string $profile): AssertionRequestController
    {
        return new AssertionRequestController(
            $this->serializer,
            $this->validator,
            $this->userEntityRepository,
            $this->credentialSourceRepository,
            $this->publicKeyCredentialRequestOptionsFactory,
            $profile
        );
    }

    public function createAssertionResponseController(): AssertionResponseController
    {
        return new AssertionResponseController(
            $this->publicKeyCredentialLoader,
            $this->attestationResponseValidator,
            $this->userEntityRepository,
            $this->credentialSourceRepository
        );
    }
}
