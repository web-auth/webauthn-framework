<?php

declare(strict_types=1);

namespace Webauthn\ConformanceToolset\Controller;

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
    
    public function __construct(private HttpMessageFactoryInterface $httpMessageFactory, private SerializerInterface $serializer, private ValidatorInterface $validator, private PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory, private PublicKeyCredentialLoader $publicKeyCredentialLoader, private AuthenticatorAssertionResponseValidator $attestationResponseValidator, private LoggerInterface $logger, private CacheItemPoolInterface $cacheItemPool, private PublicKeyCredentialUserEntityRepository $publicKeyCredentialUserEntityRepository, private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository)
    {
    }

    
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
