<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service\Fixture;

use Webauthn\Bundle\Repository\CanSaveCredentialRecord;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialUserEntity;

final class SaveableInMemoryCredentialRepository implements CredentialRecordRepositoryInterface, CanSaveCredentialRecord
{
    /**
     * @var array<string, CredentialRecord>
     */
    private array $records = [];

    /**
     * @param list<CredentialRecord> $initialRecords
     */
    public function __construct(array $initialRecords = [])
    {
        foreach ($initialRecords as $record) {
            $this->records[$record->publicKeyCredentialId] = $record;
        }
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        return $this->records[$publicKeyCredentialId] ?? null;
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

    public function saveCredentialRecord(CredentialRecord $credentialRecord): void
    {
        $this->records[$credentialRecord->publicKeyCredentialId] = $credentialRecord;
    }

    public function has(string $publicKeyCredentialId): bool
    {
        return isset($this->records[$publicKeyCredentialId]);
    }
}
