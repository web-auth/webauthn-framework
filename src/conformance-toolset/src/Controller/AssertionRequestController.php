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
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\ConformanceToolset\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class AssertionRequestController
{
    #[Pure]
    public function __construct(private SerializerInterface $serializer, private ValidatorInterface $validator, private PublicKeyCredentialUserEntityRepository $userEntityRepository, private PublicKeyCredentialSourceRepository $credentialSourceRepository, private PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory, private string $profile, private string $sessionParameterName, private LoggerInterface $logger, private CacheItemPoolInterface $cacheItemPool)
    {
    }

    public function __invoke(Request $request): Response
    {
        try {
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $creationOptionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);
            $extensions = $creationOptionsRequest->extensions;
            if (is_array($extensions)) {
                $extensions = AuthenticationExtensionsClientInputs::createFromArray($extensions);
            }
            $userEntity = $this->getUserEntity($creationOptionsRequest);
            $allowedCredentials = null === $userEntity ? [] : $this->getCredentials($userEntity);
            $publicKeyCredentialRequestOptions = $this->publicKeyCredentialRequestOptionsFactory->create(
                $this->profile,
                $allowedCredentials,
                $creationOptionsRequest->userVerification,
                $extensions
            );
            $data = array_merge(
                ['status' => 'ok', 'errorMessage' => ''],
                $publicKeyCredentialRequestOptions->jsonSerialize()
            );
            $item = $this->cacheItemPool->getItem($this->sessionParameterName);
            $item->set(['options' => $publicKeyCredentialRequestOptions, 'userEntity' => $userEntity]);
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

    private function getUserEntity(ServerPublicKeyCredentialRequestOptionsRequest $creationOptionsRequest): ?PublicKeyCredentialUserEntity
    {
        $username = $creationOptionsRequest->username;
        if (null === $username) {
            return null;
        }
        $userEntity = $this->userEntityRepository->findOneByUsername($username);
        Assertion::notNull($userEntity, 'User not found');

        return $userEntity;
    }

    private function getServerPublicKeyCredentialRequestOptionsRequest(string $content): ServerPublicKeyCredentialRequestOptionsRequest
    {
        $data = $this->serializer->deserialize(
            $content,
            ServerPublicKeyCredentialRequestOptionsRequest::class,
            'json',
            [AbstractObjectNormalizer::DISABLE_TYPE_ENFORCEMENT => true]
        );
        Assertion::isInstanceOf($data, ServerPublicKeyCredentialRequestOptionsRequest::class, 'Invalid data');
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
