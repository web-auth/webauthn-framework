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

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @group unit
 * @group Fido2
 */
class EntityTest extends TestCase
{
    /**
     * @test
     *
     * @covers \Webauthn\PublicKeyCredentialEntity
     * @covers \Webauthn\PublicKeyCredentialUserEntity
     */
    public function anPublicKeyCredentialUserEntityCanBeCreatedAndValueAccessed(): void
    {
        $user = new PublicKeyCredentialUserEntity('name', 'id', 'display_name', 'icon');

        static::assertEquals('name', $user->getName());
        static::assertEquals('display_name', $user->getDisplayName());
        static::assertEquals('icon', $user->getIcon());
        static::assertEquals('id', $user->getId());
        static::assertEquals('{"name":"name","icon":"icon","id":"aWQ=","displayName":"display_name"}', json_encode($user));
    }

    /**
     * @test
     *
     * @covers \Webauthn\PublicKeyCredentialEntity
     * @covers \Webauthn\PublicKeyCredentialRpEntity
     */
    public function anPublicKeyCredentialRpEntityCanBeCreatedAndValueAccessed(): void
    {
        $rp = new PublicKeyCredentialRpEntity('name', 'id', 'icon');

        static::assertEquals('name', $rp->getName());
        static::assertEquals('icon', $rp->getIcon());
        static::assertEquals('id', $rp->getId());
        static::assertEquals('{"name":"name","icon":"icon","id":"id"}', json_encode($rp));
    }
}
