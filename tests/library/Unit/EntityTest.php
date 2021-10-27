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

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @internal
 */
final class EntityTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialUserEntityCanBeCreatedAndValueAccessed(): void
    {
        $user = new PublicKeyCredentialUserEntity('name', 'id', 'display_name', 'icon');

        static::assertSame('name', $user->getName());
        static::assertSame('display_name', $user->getDisplayName());
        static::assertSame('icon', $user->getIcon());
        static::assertSame('id', $user->getId());
        static::assertSame(
            '{"name":"name","icon":"icon","id":"aWQ=","displayName":"display_name"}',
            json_encode($user)
        );
    }

    /**
     * @test
     */
    public function anPublicKeyCredentialRpEntityCanBeCreatedAndValueAccessed(): void
    {
        $rp = new PublicKeyCredentialRpEntity('name', 'id', 'icon');

        static::assertSame('name', $rp->getName());
        static::assertSame('icon', $rp->getIcon());
        static::assertSame('id', $rp->getId());
        static::assertSame('{"name":"name","icon":"icon","id":"id"}', json_encode($rp));
    }
}
