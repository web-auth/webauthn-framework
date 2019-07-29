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

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Handler\AbstractCreationSuccessHandler;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class CreationSuccessHandler extends AbstractCreationSuccessHandler
{
    /**
     * @var UserRepository
     */
    private $userRepository;

    public function __construct(PublicKeyCredentialUserEntityRepository $userEntityRepository, PublicKeyCredentialSourceRepository $credentialSourceRepository, UserRepository $userRepository)
    {
        parent::__construct($userEntityRepository, $credentialSourceRepository);
        $this->userRepository = $userRepository;
    }

    protected function createUserAndSave(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): UserInterface
    {
        $user = new User(
            $publicKeyCredentialUserEntity->getId(),
            $publicKeyCredentialUserEntity->getName(),
            ['ROLE_USER']
        );
        $this->userRepository->saveUser($user);

        return $user;
    }
}
