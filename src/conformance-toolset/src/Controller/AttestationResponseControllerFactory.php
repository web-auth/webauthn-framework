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

namespace Webauthn\ConformanceToolset\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
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
    /**
     * @var HttpMessageFactoryInterface
     */
    private $httpMessageFactory;
    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository, PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAttestationResponseValidator $attestationResponseValidator, LoggerInterface $logger)
    {
        $this->serializer = $serializer;
        $this->validator = $validator;
        $this->publicKeyCredentialCreationOptionsFactory = $publicKeyCredentialCreationOptionsFactory;
        $this->userEntityRepository = $userEntityRepository;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->attestationResponseValidator = $attestationResponseValidator;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->logger = $logger;
    }

    public function createAttestationRequestController(string $profile, string $sessionParameterName): AttestationRequestController
    {
        return new AttestationRequestController(
            $this->serializer,
            $this->validator,
            $this->userEntityRepository,
            $this->credentialSourceRepository,
            $this->publicKeyCredentialCreationOptionsFactory,
            $profile,
            $sessionParameterName,
            $this->logger
        );
    }

    public function createAttestationResponseController(string $sessionParameterName): AttestationResponseController
    {
        return new AttestationResponseController(
            $this->httpMessageFactory,
            $this->publicKeyCredentialLoader,
            $this->attestationResponseValidator,
            $this->userEntityRepository,
            $this->credentialSourceRepository,
            $sessionParameterName,
            $this->logger
        );
    }
}
