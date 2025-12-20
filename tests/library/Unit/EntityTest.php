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
    public function publicKeyCredentialUserEntityCanBeSerializedAndDeserialized(): void
    {
        // Given
        $user = PublicKeyCredentialUserEntity::create('name', 'id', 'display_name');

        // When
        $serialized = $this->getSerializer()
            ->serialize($user, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertSame('name', $user->name);
        static::assertSame('display_name', $user->displayName);
        static::assertSame('id', $user->id);
        static::assertSame('{"id":"aWQ","name":"name","displayName":"display_name"}', $serialized);
    }

    #[Test]
    public function publicKeyCredentialRpEntityCanBeSerializedAndDeserialized(): void
    {
        // Given
        $rp = PublicKeyCredentialRpEntity::create('', 'id');

        // When
        $serialized = $this->getSerializer()
            ->serialize($rp, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertSame('', $rp->name);
        static::assertSame('id', $rp->id);
        static::assertSame('{"id":"id"}', $serialized);
    }
}
