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

use Assert\Assertion;
use InvalidArgumentException;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

final class AssertionResponseController
{
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

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAssertionResponseValidator $assertionResponseValidator, string $sessionParameterName, LoggerInterface $logger, CacheItemPoolInterface $cacheItemPool)
    {
        $this->httpMessageFactory = $httpMessageFactory;
        $this->assertionResponseValidator = $assertionResponseValidator;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
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
            Assertion::isInstanceOf($response, AuthenticatorAssertionResponse::class, 'Invalid response');
            $item = $this->cacheItemPool->getItem($this->sessionParameterName);
            if (!$item->isHit()) {
                throw new InvalidArgumentException('Unable to find the public key credential request options');
            }
            $data = $item->get();
            Assertion::isArray($data, 'Unable to find the public key credential request options');
            Assertion::keyExists($data, 'options', 'Unable to find the public key credential request options');
            $publicKeyCredentialRequestOptions = $data['options'];
            Assertion::isInstanceOf($publicKeyCredentialRequestOptions, PublicKeyCredentialRequestOptions::class, 'Unable to find the public key credential request options');
            Assertion::keyExists($data, 'userEntity', 'Unable to find the public key credential request options');
            $userEntity = $data['userEntity'];
            Assertion::isInstanceOf($userEntity, PublicKeyCredentialUserEntity::class, 'Unable to find the public key credential request options');
            $this->assertionResponseValidator->check($publicKeyCredential->getRawId(), $response, $publicKeyCredentialRequestOptions, $psr7Request, $userEntity->getId());

            return new JsonResponse(['status' => 'ok', 'errorMessage' => '']);
        } catch (Throwable $throwable) {
            return new JsonResponse(['status' => 'failed', 'errorMessage' => $throwable->getMessage()], 400);
        }
    }
}
