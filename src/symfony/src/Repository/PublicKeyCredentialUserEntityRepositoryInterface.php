<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialUserEntity;

interface PublicKeyCredentialUserEntityRepositoryInterface
{
    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity;

    public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity;
}
