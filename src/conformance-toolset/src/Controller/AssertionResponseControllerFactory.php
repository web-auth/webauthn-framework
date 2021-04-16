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

namespace Webauthn\ConformanceToolset\Controller;

use JetBrains\PhpStorm\Pure;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

final class AssertionResponseControllerFactory
{
    #[Pure]
    public function __construct(private HttpMessageFactoryInterface $httpMessageFactory, private SerializerInterface $serializer, private ValidatorInterface $validator, private PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory, private PublicKeyCredentialLoader $publicKeyCredentialLoader, private AuthenticatorAssertionResponseValidator $attestationResponseValidator, private LoggerInterface $logger, private CacheItemPoolInterface $cacheItemPool, private PublicKeyCredentialUserEntityRepository $publicKeyCredentialUserEntityRepository, private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository)
    {
    }

    #[Pure]
    public function createAssertionRequestController(string $profile, string $sessionParameterName): AssertionRequestController
    {
        return new AssertionRequestController(
            $this->serializer,
            $this->validator,
            $this->publicKeyCredentialUserEntityRepository,
            $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialRequestOptionsFactory,
            $profile,
            $sessionParameterName,
            $this->logger,
            $this->cacheItemPool
        );
    }

    #[Pure]
    public function createAssertionResponseController(string $sessionParameterName): AssertionResponseController
    {
        return new AssertionResponseController(
            $this->httpMessageFactory,
            $this->publicKeyCredentialLoader,
            $this->attestationResponseValidator,
            $sessionParameterName,
            $this->logger,
            $this->cacheItemPool
        );
    }
}
