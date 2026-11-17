<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service\Fixture;

use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialUserEntity;

final readonly class InMemoryCredentialRepository implements CredentialRecordRepositoryInterface
{
    /**
     * @param list<CredentialRecord> $records
     */
    public function __construct(
        private array $records = [],
    ) {
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        foreach ($this->records as $record) {
            if ($record->publicKeyCredentialId === $publicKeyCredentialId) {
                return $record;
            }
        }

        return null;
    }

    /**
     * @return array<CredentialRecord>
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return array_values(array_filter(
            $this->records,
            static fn (CredentialRecord $record): bool => $record->userHandle === $publicKeyCredentialUserEntity->id,
        ));
    }
}
