<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security\Handler;

use LogicException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use function Safe\sprintf;

abstract class AbstractCreationSuccessHandler implements CreationSuccessHandler
{
    /**
     * @var PublicKeyCredentialUserEntityRepository
     */
    private $userEntityRepository;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $credentialSourceRepository;

    public function __construct(PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository)
    {
        $this->userEntityRepository = $userEntityRepository;
        $this->credentialSourceRepository = $credentialSourceRepository;
    }

    public function onCreationSuccess(Request $request, ?UserInterface $user, PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, AuthenticatorAttestationResponse $authenticatorAttestationResponse, PublicKeyCredentialSource $publicKeyCredentialSource): Response
    {
        if (null !== $user) {
            throw new LogicException(sprintf('User with username "%s" already exist', $user->getUsername()));
        }
        $this->createUserAndSave($publicKeyCredentialUserEntity);
        $this->userEntityRepository->saveUserEntity($publicKeyCredentialUserEntity);
        $this->credentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);
        $data = [
            'status' => 'ok',
            'errorMessage' => '',
        ];

        return new JsonResponse($data, JsonResponse::HTTP_OK);
    }

    abstract protected function createUserAndSave(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): UserInterface;
}
