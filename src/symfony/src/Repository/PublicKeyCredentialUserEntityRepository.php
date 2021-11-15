<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialUserEntity;

interface PublicKeyCredentialUserEntityRepository
{
    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity;

    public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity;

    public function createUserEntity(
        string $username,
        string $displayName,
        ?string $icon
    ): PublicKeyCredentialUserEntity;

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void;
}
