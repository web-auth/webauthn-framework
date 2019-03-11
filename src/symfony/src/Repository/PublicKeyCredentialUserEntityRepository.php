<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialUserEntity;

interface PublicKeyCredentialUserEntityRepository
{
    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity;

    public function createUserEntity(string $username, string $displayName, ?string $icon): PublicKeyCredentialUserEntity;

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void;
}
