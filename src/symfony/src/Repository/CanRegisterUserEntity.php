<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialUserEntity;

interface CanRegisterUserEntity
{
    /**
     * @deprecated since 4.7.0 and will be removed in 5.0.0. Please use Webauthn\Bundle\Repository\CanGenerateUserEntity::generateUserEntity() instead.
     * @infection-ignore-all
     */
    public function generateNextUserEntityId(): string;

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void;
}
