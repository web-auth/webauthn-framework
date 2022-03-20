<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const JSON_THROW_ON_ERROR;
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
            '{"name":"name","icon":"icon","id":"aWQ","displayName":"display_name"}',
            json_encode($user, JSON_THROW_ON_ERROR)
        );
    }

    /**
     * @test
     */
    public function anPublicKeyCredentialRpEntityCanBeCreatedAndValueAccessed(): void
    {
        $rp = PublicKeyCredentialRpEntity::create('name', 'id', 'icon');

        static::assertSame('name', $rp->getName());
        static::assertSame('icon', $rp->getIcon());
        static::assertSame('id', $rp->getId());
        static::assertSame('{"name":"name","icon":"icon","id":"id"}', json_encode($rp, JSON_THROW_ON_ERROR));
    }
}
