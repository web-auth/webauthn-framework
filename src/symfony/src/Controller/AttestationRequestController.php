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
use function count;
use function is_array;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\AdditionalPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Handler\CreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class AttestationRequestController
{
    /**
     * @var SerializerInterface
     */
    private $serializer;

    /**
     * @var PublicKeyCredentialCreationOptionsFactory
     */
    private $publicKeyCredentialCreationOptionsFactory;

    /**
     * @var string
     */
    private $profile;

    /**
     * @var ValidatorInterface
     */
    private $validator;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $credentialSourceRepository;

    /**
     * @var OptionsStorage
     */
    private $optionsStorage;

    /**
     * @var UserEntityGuesser
     */
    private $userEntityGuesser;

    /**
     * @var CreationOptionsHandler
     */
    private $creationOptionsHandler;

    /**
     * @var FailureHandler
     */
    private $failureHandler;

    public function __construct(UserEntityGuesser $userEntityGuesser, SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialSourceRepository $credentialSourceRepository, PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory, string $profile, OptionsStorage $sessionParameterName, CreationOptionsHandler $creationOptionsHandler, FailureHandler $failureHandler)
    {
        $this->serializer = $serializer;
        $this->validator = $validator;
        $this->publicKeyCredentialCreationOptionsFactory = $publicKeyCredentialCreationOptionsFactory;
        $this->profile = $profile;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->optionsStorage = $sessionParameterName;
        $this->userEntityGuesser = $userEntityGuesser;
        $this->creationOptionsHandler = $creationOptionsHandler;
        $this->failureHandler = $failureHandler;
    }

    public function __invoke(Request $request): Response
    {
        try {
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');

            $userEntity = $this->userEntityGuesser->findUserEntity($request);
            $publicKeyCredentialCreationOptions = $this->getPublicKeyCredentialCreationOptions(
                $content,
                $userEntity
            );
            $this->optionsStorage->store($request, new StoredData($publicKeyCredentialCreationOptions, $userEntity));

            return $this->creationOptionsHandler->onCreationOptions(
                $publicKeyCredentialCreationOptions,
                $userEntity
            );
        } catch (Throwable $throwable) {
            return $this->failureHandler->onFailure($request, $throwable);
        }
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getCredentials(PublicKeyCredentialUserEntity $userEntity): array
    {
        $credentialSources = $this->credentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
            return $credential->getPublicKeyCredentialDescriptor();
        }, $credentialSources);
    }

    private function getPublicKeyCredentialCreationOptions(string $content, PublicKeyCredentialUserEntity $userEntity): PublicKeyCredentialCreationOptions
    {
        $excludedCredentials = $this->getCredentials($userEntity);
        $creationOptionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);
        $authenticatorSelection = $creationOptionsRequest->authenticatorSelection;
        if (is_array($authenticatorSelection)) {
            $authenticatorSelection = AuthenticatorSelectionCriteria::createFromArray($authenticatorSelection);
        }
        $extensions = $creationOptionsRequest->extensions;
        if (is_array($extensions)) {
            $extensions = AuthenticationExtensionsClientInputs::createFromArray($extensions);
        }

        return $this->publicKeyCredentialCreationOptionsFactory->create(
            $this->profile,
            $userEntity,
            $excludedCredentials,
            $authenticatorSelection,
            $creationOptionsRequest->attestation,
            $extensions
        );
    }

    private function getServerPublicKeyCredentialCreationOptionsRequest(string $content): AdditionalPublicKeyCredentialCreationOptionsRequest
    {
        $data = $this->serializer->deserialize($content, AdditionalPublicKeyCredentialCreationOptionsRequest::class, 'json');
        Assertion::isInstanceOf($data, AdditionalPublicKeyCredentialCreationOptionsRequest::class, 'Invalid data');
        $errors = $this->validator->validate($data);
        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath().': '.$error->getMessage();
            }
            throw new RuntimeException(implode("\n", $messages));
        }

        return $data;
    }
}
