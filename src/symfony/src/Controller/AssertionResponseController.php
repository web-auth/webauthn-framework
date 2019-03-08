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
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSourceRepository;

final class AssertionResponseController
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
     * @var AuthenticatorAssertionResponseValidator
     */
    private $assertionResponseValidator;

    public function __construct(PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAssertionResponseValidator $assertionResponseValidator, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository)
    {
        $this->assertionResponseValidator = $assertionResponseValidator;
        $this->userEntityRepository = $userEntityRepository;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
    }

    public function __invoke(Request $request): Response
    {
        try {
            $psr7Factory = new DiactorosFactory();
            $psr7Request = $psr7Factory->createRequest($request);
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
            $response = $publicKeyCredential->getResponse();
            Assertion::isInstanceOf($response, AuthenticatorAssertionResponse::class, 'Invalid response');
            $data = $request->getSession()->get('__WEBAUTHN_ATTESTATION_REQUEST__');
            $request->getSession()->remove('__WEBAUTHN_ATTESTATION_REQUEST__');
            Assertion::isArray($data, 'Unable to find the public key credential creation options');
            Assertion::keyExists($data, 'options', 'Unable to find the public key credential creation options');
            $publicKeyCredentialRequestOptions = $data['options'];
            Assertion::isInstanceOf($publicKeyCredentialRequestOptions, PublicKeyCredentialRequestOptions::class, 'Unable to find the public key credential creation options');
            Assertion::keyExists($data, 'userHandle', 'Unable to find the public key credential creation options');
            $userHandle = $data['userHandle'];
            Assertion::string($userHandle, 'Unable to find the public key credential creation options');
            Assertion::notEmpty($userHandle, 'Unable to find the public key credential creation options');
            $this->assertionResponseValidator->check($publicKeyCredential->getId(), $response, $publicKeyCredentialRequestOptions, $psr7Request, $userHandle);

            return new JsonResponse(['status' => 'ok', 'errorMessage' => '']);
        } catch (\Throwable $throwable) {
            return new JsonResponse(['status' => 'failed', 'errorMessage' => $throwable->getMessage()], 400);
        }
    }
}
