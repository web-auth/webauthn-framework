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

namespace Webauthn\Bundle\Provider;

use Webauthn\Bundle\Model\PublicKeyCredentialFakeUserEntity;

interface FakePublicKeyCredentialUserEntityProvider
{
    public function getFakeUserEntityFor(string $username): PublicKeyCredentialFakeUserEntity;
}
