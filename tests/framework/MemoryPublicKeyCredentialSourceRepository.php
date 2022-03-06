<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialUserEntity;

final class MemoryPublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface
{
    /**
     * @var PublicKeyCredentialSource[]
     */
    private ?array $sources = null;

    public function findOneByCredentialId(string $id): ?PublicKeyCredentialSource
    {
        return $this->sources[$id] ?? null;
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $userEntity): array
    {
        return [];
    }

    public function saveCredentialSource(PublicKeyCredentialSource $source): void
    {
        $this->sources[$source->getPublicKeyCredentialId()] = $source;
    }
}
