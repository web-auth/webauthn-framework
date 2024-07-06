<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class EntityTest extends AbstractTestCase
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
            '{"id":"aWQ","name":"name","displayName":"display_name","icon":"icon"}',
            $this->getSerializer()
                ->serialize($user, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
        );
    }

    #[Test]
    public function anPublicKeyCredentialRpEntityCanBeCreatedAndValueAccessed(): void
    {
        $rp = PublicKeyCredentialRpEntity::create('name', 'id', 'icon');

        static::assertSame('name', $rp->name);
        static::assertSame('icon', $rp->icon);
        static::assertSame('id', $rp->id);
        static::assertSame('{"id":"id","name":"name","icon":"icon"}', $this->getSerializer()->serialize($rp, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
    }
}
