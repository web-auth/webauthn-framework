<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class PublicKeyCredentialSourceTest extends AbstractTestCase
{
    #[Test]
    public function publicKeyCredentialSourceBackwardCompatibilityIsPreserved(): void
    {
        // Given
        $data = '{"publicKeyCredentialId":"cHVibGljS2V5Q3JlZGVudGlhbElk","type":"type","transports":["transport1","transport2"],"attestationType":"attestationType","trustPath":[],"aaguid":"014c0f17-f86f-4586-9914-2779922ba877","credentialPublicKey":"cHVibGljS2V5","userHandle":"dXNlckhhbmRsZQ","counter":123456789}';

        // When
        $source = $this->getSerializer()
            ->deserialize($data, PublicKeyCredentialSource::class, 'json');
        $serialized = $this->getSerializer()
            ->serialize($source, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertSame('publicKeyCredentialId', $source->publicKeyCredentialId);
        static::assertJsonStringEqualsJsonString($data, $serialized);
    }

    #[Test]
    public function publicKeyCredentialSourceCanBeSerialized(): void
    {
        // Given
        $source = new PublicKeyCredentialSource(
            'publicKeyCredentialId',
            'type',
            ['transport1', 'transport2'],
            'attestationType',
            EmptyTrustPath::create(),
            Uuid::fromString('02ffd35d-7f0c-46b5-9eae-851ee4807b25'),
            'publicKey',
            'userHandle',
            123_456_789,
            null,
            true,
            true,
            false
        );

        // When
        $serialized = $this->getSerializer()
            ->serialize($source, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertJsonStringEqualsJsonString(
            '{"publicKeyCredentialId":"cHVibGljS2V5Q3JlZGVudGlhbElk","type":"type","transports":["transport1","transport2"],"attestationType":"attestationType","trustPath":[],"aaguid":"02ffd35d-7f0c-46b5-9eae-851ee4807b25","credentialPublicKey":"cHVibGljS2V5","userHandle":"dXNlckhhbmRsZQ","counter":123456789,"backupEligible":true,"backupStatus":true,"uvInitialized":false}',
            $serialized
        );
    }
}
