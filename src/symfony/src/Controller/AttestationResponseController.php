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

use Assert\Assertion;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class AttestationResponseController
{
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
     * @var OptionsStorage
     */
    private $optionStorage;

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAttestationResponseValidator $attestationResponseValidator, PublicKeyCredentialSourceRepository $credentialSourceRepository, OptionsStorage $optionStorage)
    {
        $this->attestationResponseValidator = $attestationResponseValidator;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->optionStorage = $optionStorage;
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

            $storedData = $this->optionStorage->get($request);

            $publicKeyCredentialCreationOptions = $storedData->getPublicKeyCredentialOptions();
            Assertion::isInstanceOf($publicKeyCredentialCreationOptions, PublicKeyCredentialCreationOptions::class, 'Unable to find the public key credential creation options');
            $userEntity = $storedData->getPublicKeyCredentialUserEntity();
            Assertion::isInstanceOf($userEntity, PublicKeyCredentialUserEntity::class, 'Unable to find the public key credential user entity');
            $credentialSource = $this->attestationResponseValidator->check($response, $publicKeyCredentialCreationOptions, $psr7Request);

            $this->credentialSourceRepository->saveCredentialSource($credentialSource);

            return new JsonResponse(['status' => 'ok', 'errorMessage' => '']);
        } catch (Throwable $throwable) {
            return new JsonResponse(['status' => 'failed', 'errorMessage' => $throwable->getMessage()], 400);
        }
    }
}
