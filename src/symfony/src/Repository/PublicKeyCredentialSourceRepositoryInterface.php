<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @deprecated since 5.3, use CredentialRecordRepositoryInterface instead. Will be removed in 6.0.
 */
interface PublicKeyCredentialSourceRepositoryInterface
{
    /**
     * @return array<CredentialRecord|PublicKeyCredentialSource>
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array;

    public function findOneByCredentialId(
        string $publicKeyCredentialId
    ): CredentialRecord|PublicKeyCredentialSource|null;
}
