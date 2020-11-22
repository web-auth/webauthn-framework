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
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\SuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class AssertionResponseController
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
     * @var AuthenticatorAssertionResponseValidator
     */
    private $assertionResponseValidator;

    /**
     * @var HttpMessageFactoryInterface
     */
    private $httpMessageFactory;

    /**
     * @var OptionsStorage
     */
    private $optionStorage;

    /**
     * @var SuccessHandler
     */
    private $successHandler;

    /**
     * @var FailureHandler
     */
    private $failureHandler;

    public function __construct(HttpMessageFactoryInterface $httpMessageFactory, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAssertionResponseValidator $assertionResponseValidator, PublicKeyCredentialSourceRepository $credentialSourceRepository, OptionsStorage $optionStorage, SuccessHandler $successHandler, FailureHandler $failureHandler)
    {
        $this->assertionResponseValidator = $assertionResponseValidator;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->optionStorage = $optionStorage;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
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

            $storedData = $this->optionStorage->get($request);

            $publicKeyCredentialRequestOptions = $storedData->getPublicKeyCredentialOptions();
            Assertion::isInstanceOf($publicKeyCredentialRequestOptions, PublicKeyCredentialRequestOptions::class, 'Unable to find the public key credential creation options');
            $userEntity = $storedData->getPublicKeyCredentialUserEntity();
            Assertion::isInstanceOf($userEntity, PublicKeyCredentialUserEntity::class, 'Unable to find the public key credential user entity');
            $credentialSource = $this->assertionResponseValidator->check(
                '', //$credentialId,
                $response,
                $publicKeyCredentialRequestOptions,
                $psr7Request,
                '' //userHandle
            );

            $this->credentialSourceRepository->saveCredentialSource($credentialSource);

            return $this->successHandler->onSuccess($request);
        } catch (Throwable $throwable) {
            return $this->failureHandler->onFailure($request, $throwable);
        }
    }
}
