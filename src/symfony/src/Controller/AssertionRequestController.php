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
use Webauthn\Bundle\Dto\AdditionalPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Bundle\Security\Storage\StoredData;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class AssertionRequestController
{
    /**
     * @var SerializerInterface
     */
    private $serializer;

    /**
     * @var PublicKeyCredentialRequestOptionsFactory
     */
    private $publicKeyCredentialRequestOptionsFactory;

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
     * @var RequestOptionsHandler
     */
    private $requestOptionsHandler;

    /**
     * @var FailureHandler
     */
    private $failureHandler;

    public function __construct(UserEntityGuesser $userEntityGuesser, SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialSourceRepository $credentialSourceRepository, PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory, string $profile, OptionsStorage $sessionParameterName, RequestOptionsHandler $requestOptionsHandler, FailureHandler $failureHandler)
    {
        $this->serializer = $serializer;
        $this->validator = $validator;
        $this->publicKeyCredentialRequestOptionsFactory = $publicKeyCredentialRequestOptionsFactory;
        $this->profile = $profile;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->optionsStorage = $sessionParameterName;
        $this->userEntityGuesser = $userEntityGuesser;
        $this->requestOptionsHandler = $requestOptionsHandler;
        $this->failureHandler = $failureHandler;
    }

    public function __invoke(Request $request): Response
    {
        try {
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');

            $userEntity = $this->userEntityGuesser->findUserEntity($request);
            $publicKeyCredentialRequestOptions = $this->getPublicKeyCredentialRequestOptions(
                $content,
                $userEntity
            );

            $response = $this->requestOptionsHandler->onRequestOptions(
                $publicKeyCredentialRequestOptions,
                $userEntity
            );
            $this->optionsStorage->store($request, new StoredData($publicKeyCredentialRequestOptions, $userEntity), $response);

            return $response;
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

    private function getPublicKeyCredentialRequestOptions(string $content, PublicKeyCredentialUserEntity $userEntity): PublicKeyCredentialRequestOptions
    {
        $allowCredentials = $this->getCredentials($userEntity);
        $requestOptionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);
        $userVerification = $requestOptionsRequest->userVerification;
        $extensions = $requestOptionsRequest->extensions;
        if (is_array($extensions)) {
            $extensions = AuthenticationExtensionsClientInputs::createFromArray($extensions);
        }

        return $this->publicKeyCredentialRequestOptionsFactory->create(
            $this->profile,
            $allowCredentials,
            $userVerification,
            $extensions
        );
    }

    private function getServerPublicKeyCredentialRequestOptionsRequest(string $content): AdditionalPublicKeyCredentialRequestOptionsRequest
    {
        $data = $this->serializer->deserialize($content, AdditionalPublicKeyCredentialRequestOptionsRequest::class, 'json');
        Assertion::isInstanceOf($data, AdditionalPublicKeyCredentialRequestOptionsRequest::class, 'Invalid data');
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
