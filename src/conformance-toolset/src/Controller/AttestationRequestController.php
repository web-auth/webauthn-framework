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
use function count;
use function is_array;
use JetBrains\PhpStorm\Pure;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\ConformanceToolset\Dto\ServerPublicKeyCredentialCreationOptionsRequest;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class AttestationRequestController
{
    #[Pure]
    public function __construct(private SerializerInterface $serializer, private ValidatorInterface $validator, private PublicKeyCredentialUserEntityRepository $userEntityRepository, private PublicKeyCredentialSourceRepository $credentialSourceRepository, private PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory, private string $profile, private string $sessionParameterName, private LoggerInterface $logger, private CacheItemPoolInterface $cacheItemPool)
    {
    }

    public function __invoke(Request $request): Response
    {
        try {
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $creationOptionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);
            $userEntity = $this->getUserEntity($creationOptionsRequest);
            $excludedCredentials = $this->getCredentials($userEntity);
            $authenticatorSelection = $creationOptionsRequest->authenticatorSelection;
            if (is_array($authenticatorSelection)) {
                $authenticatorSelection = AuthenticatorSelectionCriteria::createFromArray($authenticatorSelection);
            }
            $extensions = $creationOptionsRequest->extensions;
            if (is_array($extensions)) {
                $extensions = AuthenticationExtensionsClientInputs::createFromArray($extensions);
            }
            $publicKeyCredentialCreationOptions = $this->publicKeyCredentialCreationOptionsFactory->create(
                $this->profile,
                $userEntity,
                $excludedCredentials,
                $authenticatorSelection,
                $creationOptionsRequest->attestation,
                $extensions
            );
            $data = array_merge(
                ['status' => 'ok', 'errorMessage' => ''],
                $publicKeyCredentialCreationOptions->jsonSerialize()
            );
            $item = $this->cacheItemPool->getItem($this->sessionParameterName);
            $item->set($publicKeyCredentialCreationOptions);
            $this->cacheItemPool->save($item);

            return new JsonResponse($data);
        } catch (Throwable $throwable) {
            $this->logger->error($throwable->getMessage());

            return new JsonResponse(['status' => 'failed', 'errorMessage' => $throwable->getMessage()], 400);
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

    private function getUserEntity(ServerPublicKeyCredentialCreationOptionsRequest $creationOptionsRequest): PublicKeyCredentialUserEntity
    {
        $username = $creationOptionsRequest->username;
        $userEntity = $this->userEntityRepository->findOneByUsername($username);
        if (null === $userEntity) {
            $userEntity = $this->userEntityRepository->createUserEntity($username, $creationOptionsRequest->displayName, null);
        }

        return $userEntity;
    }

    private function getServerPublicKeyCredentialCreationOptionsRequest(string $content): ServerPublicKeyCredentialCreationOptionsRequest
    {
        $data = $this->serializer->deserialize(
            $content,
            ServerPublicKeyCredentialCreationOptionsRequest::class,
            'json',
            [AbstractObjectNormalizer::DISABLE_TYPE_ENFORCEMENT => true]
        );
        Assertion::isInstanceOf($data, ServerPublicKeyCredentialCreationOptionsRequest::class, 'Invalid data');
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
