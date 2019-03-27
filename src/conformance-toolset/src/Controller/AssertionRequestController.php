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

namespace Webauthn\ConformanceToolset\Controller;

use Assert\Assertion;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\ConformanceToolset\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
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
     * @var PublicKeyCredentialUserEntityRepository
     */
    private $userEntityRepository;
    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $credentialSourceRepository;
    /**
     * @var string
     */
    private $sessionParameterName;

    public function __construct(SerializerInterface $serializer, ValidatorInterface $validator, PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository, PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory, string $profile, string $sessionParameterName)
    {
        $this->serializer = $serializer;
        $this->validator = $validator;
        $this->publicKeyCredentialRequestOptionsFactory = $publicKeyCredentialRequestOptionsFactory;
        $this->profile = $profile;
        $this->userEntityRepository = $userEntityRepository;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->sessionParameterName = $sessionParameterName;
    }

    public function __invoke(Request $request): Response
    {
        try {
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $creationOptionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);
            $userEntity = $this->getUserEntity($creationOptionsRequest);
            $allowedCredentials = $this->getCredentials($userEntity);
            $publicKeyCredentialRequestOptions = $this->publicKeyCredentialRequestOptionsFactory->create(
                $this->profile,
                $allowedCredentials,
                $creationOptionsRequest->userVerification
            );
            $data = array_merge(
                ['status' => 'ok', 'errorMessage' => ''],
                $publicKeyCredentialRequestOptions->jsonSerialize()
            );
            $request->getSession()->set($this->sessionParameterName, ['options' => $publicKeyCredentialRequestOptions, 'userEntity' => $userEntity]);

            return new JsonResponse($data);
        } catch (\Throwable $throwable) {
            return new JsonResponse(['status' => 'failed', 'errorMessage' => $throwable->getMessage()], 400);
        }
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getCredentials(PublicKeyCredentialUserEntity $userEntity): array
    {
        $credentialSources = $this->credentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(function (PublicKeyCredentialSource $credential) {
            return $credential->getPublicKeyCredentialDescriptor();
        }, $credentialSources);
    }

    private function getUserEntity(ServerPublicKeyCredentialRequestOptionsRequest $creationOptionsRequest): PublicKeyCredentialUserEntity
    {
        $username = $creationOptionsRequest->username;
        $userEntity = $this->userEntityRepository->findOneByUsername($username);
        Assertion::notNull($userEntity, 'User not found');

        return $userEntity;
    }

    private function getServerPublicKeyCredentialRequestOptionsRequest(string $content): ServerPublicKeyCredentialRequestOptionsRequest
    {
        $data = $this->serializer->deserialize($content, ServerPublicKeyCredentialRequestOptionsRequest::class, 'json');
        Assertion::isInstanceOf($data, ServerPublicKeyCredentialRequestOptionsRequest::class, 'Invalid data');
        $errors = $this->validator->validate($data);
        if (\count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath().': '.$error->getMessage();
            }
            throw new \RuntimeException(implode("\n", $messages));
        }

        return $data;
    }
}
