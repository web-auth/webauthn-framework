<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialUserEntity;

interface CanGenerateUserEntity
{
    public function generateUserEntity(?string $username, ?string $displayName): PublicKeyCredentialUserEntity;
}
