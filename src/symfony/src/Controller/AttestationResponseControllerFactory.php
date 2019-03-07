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
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

final class AttestationResponseControllerFactory
{
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

    public function __construct(SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository, PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAttestationResponseValidator $attestationResponseValidator)
    {
        $this->serializer = $serializer;
        $this->validator = $validator;
        $this->publicKeyCredentialCreationOptionsFactory = $publicKeyCredentialCreationOptionsFactory;
        $this->userEntityRepository = $userEntityRepository;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->attestationResponseValidator = $attestationResponseValidator;
    }

    public function createAttestationRequestController(string $profile): AttestationRequestController
    {
        return new AttestationRequestController(
            $this->serializer,
            $this->validator,
            $this->userEntityRepository,
            $this->credentialSourceRepository,
            $this->publicKeyCredentialCreationOptionsFactory,
            $profile
        );
    }

    public function createAttestationResponseController(): AttestationResponseController
    {
        return new AttestationResponseController(
            $this->publicKeyCredentialLoader,
            $this->attestationResponseValidator,
            $this->userEntityRepository,
            $this->credentialSourceRepository
        );
    }
}
