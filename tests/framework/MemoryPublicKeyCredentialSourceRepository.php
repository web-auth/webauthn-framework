<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests;

use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialUserEntity;

final class MemoryPublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface
{
    /**
     * @var PublicKeyCredentialSource[]
     */
    private $sources;

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
