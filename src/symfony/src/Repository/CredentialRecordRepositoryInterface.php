<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Repository interface for storing and retrieving credential records.
 *
 * @see https://www.w3.org/TR/webauthn-3/#credential-record
 */
interface CredentialRecordRepositoryInterface
{
    /**
     * @return array<CredentialRecord>
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array;

    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord;
}
