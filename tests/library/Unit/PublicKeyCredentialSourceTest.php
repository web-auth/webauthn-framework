<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

/**
 * @internal
 */
final class PublicKeyCredentialSourceTest extends AbstractTestCase
{
    #[Test]
    public function backwardCompatibilityIsEnsured(): void
    {
        $data = '{"publicKeyCredentialId":"cHVibGljS2V5Q3JlZGVudGlhbElk","type":"type","transports":["transport1","transport2"],"attestationType":"attestationType","trustPath":{"type":"Webauthn\\\\TrustPath\\\\EmptyTrustPath"},"aaguid":"014c0f17-f86f-4586-9914-2779922ba877","credentialPublicKey":"cHVibGljS2V5","userHandle":"dXNlckhhbmRsZQ","counter":123456789}';
        $source = $this->getSerializer()
            ->deserialize($data, PublicKeyCredentialSource::class, 'json');

        static::assertSame('publicKeyCredentialId', $source->publicKeyCredentialId);
    }

    #[Test]
    public function objectSerialization(): void
    {
        $source = PublicKeyCredentialSource::create(
            'publicKeyCredentialId',
            'type',
            ['transport1', 'transport2'],
            'attestationType',
            EmptyTrustPath::create(),
            Uuid::fromString('02ffd35d-7f0c-46b5-9eae-851ee4807b25'),
            'publicKey',
            'userHandle',
            123_456_789
        );

        static::assertSame(
            '{"publicKeyCredentialId":"cHVibGljS2V5Q3JlZGVudGlhbElk","type":"type","transports":["transport1","transport2"],"attestationType":"attestationType","trustPath":{"type":"Webauthn\\\\TrustPath\\\\EmptyTrustPath"},"aaguid":"02ffd35d-7f0c-46b5-9eae-851ee4807b25","credentialPublicKey":"cHVibGljS2V5","userHandle":"dXNlckhhbmRsZQ","counter":123456789,"otherUI":null}',
            json_encode($source, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
        );
    }
}
