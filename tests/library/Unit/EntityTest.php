<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class EntityTest extends TestCase
{
    #[Test]
    public function anPublicKeyCredentialUserEntityCanBeCreatedAndValueAccessed(): void
    {
        $user = PublicKeyCredentialUserEntity::create('name', 'id', 'display_name', 'icon');

        static::assertSame('name', $user->name);
        static::assertSame('display_name', $user->displayName);
        static::assertSame('icon', $user->icon);
        static::assertSame('id', $user->id);
        static::assertSame(
            '{"name":"name","icon":"icon","id":"aWQ","displayName":"display_name"}',
            json_encode($user, JSON_THROW_ON_ERROR)
        );
    }

    #[Test]
    public function anPublicKeyCredentialRpEntityCanBeCreatedAndValueAccessed(): void
    {
        $rp = PublicKeyCredentialRpEntity::create('name', 'id', 'icon');

        static::assertSame('name', $rp->name);
        static::assertSame('icon', $rp->icon);
        static::assertSame('id', $rp->id);
        static::assertSame('{"name":"name","icon":"icon","id":"id"}', json_encode($rp, JSON_THROW_ON_ERROR));
    }
}
