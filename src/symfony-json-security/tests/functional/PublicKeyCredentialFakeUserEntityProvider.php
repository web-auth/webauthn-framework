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

namespace Webauthn\JsonSecurityBundle\Tests\Functional;

use Webauthn\JsonSecurityBundle\Model\PublicKeyCredentialFakeUserEntity;
use Webauthn\JsonSecurityBundle\Provider\FakePublicKeyCredentialUserEntityProvider;
use Webauthn\PublicKeyCredentialDescriptor;

final class PublicKeyCredentialFakeUserEntityProvider implements FakePublicKeyCredentialUserEntityProvider
{
    public function getFakeUserEntityFor(string $username): PublicKeyCredentialFakeUserEntity
    {
        return new PublicKeyCredentialFakeUserEntity(
            $username,
            hash('sha256', $username, true),
            'Fake User '.$username,
            [
                new PublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, hash('sha256', $username.'Key #1', true)),
                new PublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, hash('sha256', $username.'Key #2', true)),
                new PublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, hash('sha256', $username.'Key #3', true)),
            ]
        );
    }
}
