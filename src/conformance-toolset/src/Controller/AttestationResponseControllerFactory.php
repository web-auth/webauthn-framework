<?php

declare(strict_types=1);

namespace Webauthn\ConformanceToolset\Controller;

use JetBrains\PhpStorm\Pure;
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
    #[Pure]
    public function __construct(private HttpMessageFactoryInterface $httpMessageFactory, private SerializerInterface $serializer, private ValidatorInterface $validator, private PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory, private PublicKeyCredentialLoader $publicKeyCredentialLoader, private AuthenticatorAttestationResponseValidator $attestationResponseValidator, private LoggerInterface $logger, private CacheItemPoolInterface $cacheItemPool, private PublicKeyCredentialUserEntityRepository $publicKeyCredentialUserEntityRepository, private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository)
    {
    }

    #[Pure]
    public function createAttestationRequestController(string $profile, string $sessionParameterName): AttestationRequestController
    {
        return new AttestationRequestController(
            $this->serializer,
            $this->validator,
            $this->publicKeyCredentialUserEntityRepository,
            $this->publicKeyCredentialSourceRepository,
            $this->publicKeyCredentialCreationOptionsFactory,
            $profile,
            $sessionParameterName,
            $this->logger,
            $this->cacheItemPool
        );
    }

    #[Pure]
    public function createAttestationResponseController(string $sessionParameterName): AttestationResponseController
    {
        return new AttestationResponseController(
            $this->httpMessageFactory,
            $this->publicKeyCredentialLoader,
            $this->attestationResponseValidator,
            $this->publicKeyCredentialUserEntityRepository,
            $this->publicKeyCredentialSourceRepository,
            $sessionParameterName,
            $this->logger,
            $this->cacheItemPool
        );
    }
}
