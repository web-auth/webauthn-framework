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

namespace Webauthn\Bundle\Service;

use Assert\Assertion;
use Assert\AssertionFailedException;
use RuntimeException;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\AdditionalPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @deprecated This class is deprecated and will be removed in 4.0
 */
class AuthenticatorRegistrationHelper
{
    /**
     * @var PublicKeyCredentialCreationOptionsFactory
     */
    private $publicKeyCredentialCreationOptionsFactory;

    /**
     * @var SerializerInterface
     */
    private $serializer;

    /**
     * @var ValidatorInterface
     */
    private $validator;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $publicKeyCredentialSourceRepository;

    /**
     * @var PublicKeyCredentialLoader
     */
    private $publicKeyCredentialLoader;

    /**
     * @var AuthenticatorAttestationResponseValidator
     */
    private $authenticatorAttestationResponseValidator;

    /**
     * @var SessionStorage
     */
    private $optionsStorage;

    /**
     * @var HttpMessageFactoryInterface
     */
    private $httpMessageFactory;

    /**
     * @var string[]
     */
    private $securedRelyingPartyId;

    public function __construct(PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory, SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, PublicKeyCredentialLoader $publicKeyCredentialLoader, AuthenticatorAttestationResponseValidator $authenticatorAttestationResponseValidator, SessionStorage $optionsStorage, HttpMessageFactoryInterface $httpMessageFactory, array $securedRelyingPartyId = [])
    {
        $this->publicKeyCredentialCreationOptionsFactory = $publicKeyCredentialCreationOptionsFactory;
        $this->serializer = $serializer;
        $this->validator = $validator;
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->authenticatorAttestationResponseValidator = $authenticatorAttestationResponseValidator;
        $this->optionsStorage = $optionsStorage;
        $this->httpMessageFactory = $httpMessageFactory;
        $this->securedRelyingPartyId = $securedRelyingPartyId;
    }

    /**
     * @throws AssertionFailedException
     */
    public function generateOptions(PublicKeyCredentialUserEntity $userEntity, Request $request, string $profile = 'default'): PublicKeyCredentialCreationOptions
    {
        $content = $request->getContent();
        Assertion::string($content, 'Invalid data');
        $creationOptionsRequest = $this->getAdditionalPublicKeyCredentialCreationOptionsRequest($content);
        $authenticatorSelection = null !== $creationOptionsRequest->authenticatorSelection ? AuthenticatorSelectionCriteria::createFromArray($creationOptionsRequest->authenticatorSelection) : null;
        $extensions = null !== $creationOptionsRequest->extensions ? AuthenticationExtensionsClientInputs::createFromArray($creationOptionsRequest->extensions) : null;
        $publicKeyCredentialCreationOptions = $this->publicKeyCredentialCreationOptionsFactory->create(
            $profile,
            $userEntity,
            $this->getUserAuthenticatorList($userEntity),
            $authenticatorSelection,
            $creationOptionsRequest->attestation,
            $extensions
        );
        $this->optionsStorage->store($request, new StoredData($publicKeyCredentialCreationOptions, $userEntity));

        return $publicKeyCredentialCreationOptions;
    }

    /**
     * @throws Throwable
     */
    public function validateResponse(PublicKeyCredentialUserEntity $user, Request $request): PublicKeyCredentialSource
    {
        $storedData = $this->optionsStorage->get($request);
        $assertion = $request->getContent();
        Assertion::string($assertion, 'Invalid assertion');
        $assertion = trim($assertion);
        $publicKeyCredential = $this->publicKeyCredentialLoader->load($assertion);
        $response = $publicKeyCredential->getResponse();
        if (!$response instanceof AuthenticatorAttestationResponse) {
            throw new AuthenticationException('Invalid assertion');
        }

        $psr7Request = $this->httpMessageFactory->createRequest($request);

        $options = $storedData->getPublicKeyCredentialOptions();
        Assertion::isInstanceOf($options, PublicKeyCredentialCreationOptions::class, 'Invalid options');
        $userEntity = $storedData->getPublicKeyCredentialUserEntity();
        Assertion::notNull($userEntity, 'Invalid user');
        Assertion::eq($user->getId(), $userEntity->getId(), PublicKeyCredentialUserEntity::class, 'Invalid user');

        $publicKeyCredentialSource = $this->authenticatorAttestationResponseValidator->check(
            $response,
            $options,
            $psr7Request,
            $this->securedRelyingPartyId
        );
        $this->publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);

        return $publicKeyCredentialSource;
    }

    /**
     * @throws AssertionFailedException
     */
    private function getAdditionalPublicKeyCredentialCreationOptionsRequest(string $content): AdditionalPublicKeyCredentialCreationOptionsRequest
    {
        $data = $this->serializer->deserialize($content, AdditionalPublicKeyCredentialCreationOptionsRequest::class, 'json');
        Assertion::isInstanceOf($data, AdditionalPublicKeyCredentialCreationOptionsRequest::class, 'Invalid data');
        $errors = $this->validator->validate($data);
        if (\count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath().': '.$error->getMessage();
            }
            throw new RuntimeException(implode("\n", $messages));
        }

        return $data;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getUserAuthenticatorList(PublicKeyCredentialUserEntity $userEntity): array
    {
        $list = $this->publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(static function (PublicKeyCredentialSource $publicKeyCredentialSource): PublicKeyCredentialDescriptor {
            return $publicKeyCredentialSource->getPublicKeyCredentialDescriptor();
        }, $list);
    }
}
