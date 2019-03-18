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

namespace Webauthn\ConformanceToolset\Tests\Functional;

use Ramsey\Uuid\Uuid;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository as PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\PublicKeyCredentialUserEntity;

final class PublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepositoryInterface
{
    private $users = [];

    public function __construct()
    {
        $this->users = [
            'username' => new PublicKeyCredentialUserEntity('username', 'foo', 'Foo BAR'),
        ];
    }

    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
    {
        return $this->users[$username] ?? null;
    }

    public function createUserEntity(string $username, string $displayName, ?string $icon): PublicKeyCredentialUserEntity
    {
        return new PublicKeyCredentialUserEntity(
            $username,
            Uuid::uuid4()->toString(),
            $displayName,
            $icon
        );
    }

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void
    {
        $this->users[$userEntity->getName()] = $userEntity;
    }
}
