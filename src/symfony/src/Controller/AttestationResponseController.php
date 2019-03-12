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

use Assert\Assertion;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSource;
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

    public function __construct(PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAttestationResponseValidator $attestationResponseValidator, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository)
    {
        $this->attestationResponseValidator = $attestationResponseValidator;
        $this->userEntityRepository = $userEntityRepository;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
    }

    public function __invoke(Request $request): Response
    {
        try {
            $psr17Factory = new Psr17Factory();
            $psrHttpFactory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);
            $psr7Request = $psrHttpFactory->createRequest($request);
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
            $response = $publicKeyCredential->getResponse();
            Assertion::isInstanceOf($response, AuthenticatorAttestationResponse::class, 'Invalid response');
            $publicKeyCredentialCreationOptions = $request->getSession()->get('__WEBAUTHN_ATTESTATION_REQUEST__');
            $request->getSession()->remove('__WEBAUTHN_ATTESTATION_REQUEST__');
            Assertion::isInstanceOf($publicKeyCredentialCreationOptions, PublicKeyCredentialCreationOptions::class, 'Unable to find the public key credential creation options');
            $this->attestationResponseValidator->check($response, $publicKeyCredentialCreationOptions, $psr7Request);
            $this->userEntityRepository->saveUserEntity($publicKeyCredentialCreationOptions->getUser());
            $credentialSource = new PublicKeyCredentialSource(
                $publicKeyCredential->getId(),
                $publicKeyCredential->getType(),
                [],
                $response->getAttestationObject()->getAttStmt()->getType(),
                $response->getAttestationObject()->getAttStmt()->getTrustPath(),
                $response->getAttestationObject()->getAuthData()->getAttestedCredentialData()->getAaguid(),
                $response->getAttestationObject()->getAuthData()->getAttestedCredentialData()->getCredentialPublicKey(),
                $publicKeyCredentialCreationOptions->getUser()->getId(),
                $response->getAttestationObject()->getAuthData()->getSignCount()
            );
            $this->credentialSourceRepository->saveCredentialSource($credentialSource);

            return new JsonResponse(['status' => 'ok', 'errorMessage' => '']);
        } catch (\Throwable $throwable) {
            return new JsonResponse(['status' => 'failed', 'errorMessage' => $throwable->getMessage()], 400);
        }
    }
}
