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

use Assert\Assertion;
use InvalidArgumentException;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
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
     * @var string
     */
    private $sessionParameterName;
    /**
     * @var LoggerInterface
     */
    private $logger;
    /**
     * @var CacheItemPoolInterface
     */
    private $cacheItemPool;

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAttestationResponseValidator $attestationResponseValidator, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository, string $sessionParameterName, LoggerInterface $logger, CacheItemPoolInterface $cacheItemPool)
    {
        $this->attestationResponseValidator = $attestationResponseValidator;
        $this->userEntityRepository = $userEntityRepository;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->sessionParameterName = $sessionParameterName;
        $this->logger = $logger;
        $this->cacheItemPool = $cacheItemPool;
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

            $item = $this->cacheItemPool->getItem($this->sessionParameterName);
            if (!$item->isHit()) {
                throw new InvalidArgumentException('Unable to find the public key credential creation options');
            }
            $publicKeyCredentialCreationOptions = $item->get();
            Assertion::isInstanceOf($publicKeyCredentialCreationOptions, PublicKeyCredentialCreationOptions::class, 'Unable to find the public key credential creation options');
            $credentialSource = $this->attestationResponseValidator->check($response, $publicKeyCredentialCreationOptions, $psr7Request);

            $this->userEntityRepository->saveUserEntity($publicKeyCredentialCreationOptions->getUser());
            $this->credentialSourceRepository->saveCredentialSource($credentialSource);

            return new JsonResponse(['status' => 'ok', 'errorMessage' => '']);
        } catch (Throwable $throwable) {
            $this->logger->error($throwable->getMessage());

            return new JsonResponse(['status' => 'failed', 'errorMessage' => $throwable->getMessage()], 400);
        }
    }
}
