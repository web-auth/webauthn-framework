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

use Psr\Cache\CacheItemPoolInterface;
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

    /**
     * @var CacheItemPoolInterface
     */
    private $cacheItemPool;

    /**
     * @var PublicKeyCredentialUserEntityRepository|null
     */
    private $publicKeyCredentialUserEntityRepository;

    /**
     * @var PublicKeyCredentialSourceRepository|null
     */
    private $publicKeyCredentialSourceRepository;

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAttestationResponseValidator $attestationResponseValidator, LoggerInterface $logger, CacheItemPoolInterface $cacheItemPool, ?PublicKeyCredentialUserEntityRepository $publicKeyCredentialUserEntityRepository = null, ?PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository = null)
    {
        $this->serializer = $serializer;
        $this->validator = $validator;
        $this->publicKeyCredentialCreationOptionsFactory = $publicKeyCredentialCreationOptionsFactory;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->attestationResponseValidator = $attestationResponseValidator;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->logger = $logger;
        $this->cacheItemPool = $cacheItemPool;
        $this->publicKeyCredentialUserEntityRepository = $publicKeyCredentialUserEntityRepository;
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;
    }

    public function createAttestationRequestController(?PublicKeyCredentialUserEntityRepository $publicKeyCredentialUserEntityRepository, ?PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, string $profile, string $sessionParameterName): AttestationRequestController
    {
        if (null !== $publicKeyCredentialUserEntityRepository) {
            @trigger_error('The argument "$publicKeyCredentialUserEntityRepository" is deprecated since 2.1 and will be removed en v3.0. Set null instead and inject it through the constructor', E_USER_DEPRECATED);
        }
        if (null !== $publicKeyCredentialSourceRepository) {
            @trigger_error('The argument "$publicKeyCredentialSourceRepository" is deprecated since 2.1 and will be removed en v3.0. Set null instead and inject it through the constructor', E_USER_DEPRECATED);
        }

        return new AttestationRequestController(
            $this->serializer,
            $this->validator,
            $publicKeyCredentialUserEntityRepository ?? $this->publicKeyCredentialUserEntityRepository,
            $publicKeyCredentialSourceRepository ?? $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialCreationOptionsFactory,
            $profile,
            $sessionParameterName,
            $this->logger,
            $this->cacheItemPool
        );
    }

    public function createAttestationResponseController(?PublicKeyCredentialUserEntityRepository $publicKeyCredentialUserEntityRepository, ?PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, string $sessionParameterName): AttestationResponseController
    {
        if (null !== $publicKeyCredentialUserEntityRepository) {
            @trigger_error('The argument "$publicKeyCredentialUserEntityRepository" is deprecated since 2.1 and will be removed en v3.0. Set null instead and inject it through the constructor', E_USER_DEPRECATED);
        }
        if (null !== $publicKeyCredentialSourceRepository) {
            @trigger_error('The argument "$publicKeyCredentialSourceRepository" is deprecated since 2.1 and will be removed en v3.0. Set null instead and inject it through the constructor', E_USER_DEPRECATED);
        }

        return new AttestationResponseController(
            $this->httpMessageFactory,
            $this->publicKeyCredentialLoader,
            $this->attestationResponseValidator,
            $publicKeyCredentialUserEntityRepository ?? $this->publicKeyCredentialUserEntityRepository,
            $publicKeyCredentialSourceRepository ?? $this->publicKeyCredentialSourceRepository,
            $sessionParameterName,
            $this->logger,
            $this->cacheItemPool
        );
    }
}
