<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

interface PublicKeyCredentialSourceRepositoryInterface
{
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void;

    /**
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array;

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource;
}
