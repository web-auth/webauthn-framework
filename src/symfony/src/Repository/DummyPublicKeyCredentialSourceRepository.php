<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * This dummy Public Key Credential Source Repository is set to allow the bundle to be installed
 * even if the real repository is not set in the configuration file.
 */
class DummyPublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepository
{
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        //Does nothing
    }

    /**
     * {@inheritdoc}
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return [];
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        return null;
    }
}
