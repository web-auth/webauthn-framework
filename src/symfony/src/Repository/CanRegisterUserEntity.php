<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialUserEntity;

interface CanRegisterUserEntity
{
    public function generateNextUserEntityId(): string;

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void;
}
