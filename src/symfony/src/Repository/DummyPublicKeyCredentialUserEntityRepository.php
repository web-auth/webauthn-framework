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

use Webauthn\PublicKeyCredentialUserEntity;

/**
 * This dummy Public Key User Entity Source Repository is set to allow the bundle to be installed
 * even if the real repository is not set in the configuration file
 */
class DummyPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository
{
    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
    {
        return null;
    }

    public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
    {
        return null;
    }

    public function createUserEntity(string $username, string $displayName, ?string $icon): PublicKeyCredentialUserEntity
    {
        return new PublicKeyCredentialUserEntity($username, '', $displayName, $icon);
    }

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void
    {
        //Does nothing
    }
}
