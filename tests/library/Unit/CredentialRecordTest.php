<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class CredentialRecordTest extends AbstractTestCase
{
    #[Test]
    public function aCredentialRecordCanBeCreatedAndValueAccessed(): void
    {
        $credentialId = 'credential-id';
        $userHandle = 'user-handle';
        $counter = 10;
        $aaguid = Uuid::v4();
        $publicKey = 'public-key';
        $transports = ['usb', 'nfc'];

        $credentialRecord = CredentialRecord::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transports,
            'none',
            EmptyTrustPath::create(),
            $aaguid,
            $publicKey,
            $userHandle,
            $counter
        );

        static::assertSame($credentialId, $credentialRecord->publicKeyCredentialId);
        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $credentialRecord->type);
        static::assertSame($transports, $credentialRecord->transports);
        static::assertSame('none', $credentialRecord->attestationType);
        static::assertInstanceOf(EmptyTrustPath::class, $credentialRecord->trustPath);
        static::assertSame($aaguid, $credentialRecord->aaguid);
        static::assertSame($publicKey, $credentialRecord->credentialPublicKey);
        static::assertSame($userHandle, $credentialRecord->userHandle);
        static::assertSame($counter, $credentialRecord->counter);
    }

    #[Test]
    public function aCredentialRecordCanBeSerializedAndDeserialized(): void
    {
        $credentialId = 'credential-id';
        $userHandle = 'user-handle';
        $counter = 10;
        $aaguid = Uuid::v4();
        $publicKey = 'public-key';
        $transports = ['usb', 'nfc'];

        $credentialRecord = CredentialRecord::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transports,
            'none',
            EmptyTrustPath::create(),
            $aaguid,
            $publicKey,
            $userHandle,
            $counter,
            null,
            true,
            false,
            true,
            'example.com'
        );

        $json = $this->getSerializer()
            ->serialize($credentialRecord, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        $deserialized = $this->getSerializer()
            ->deserialize($json, CredentialRecord::class, 'json');

        static::assertInstanceOf(CredentialRecord::class, $deserialized);
        static::assertSame($credentialId, $deserialized->publicKeyCredentialId);
        static::assertSame($userHandle, $deserialized->userHandle);
        static::assertSame($counter, $deserialized->counter);
        static::assertTrue($deserialized->backupEligible);
        static::assertFalse($deserialized->backupStatus);
        static::assertTrue($deserialized->uvInitialized);
        static::assertSame('example.com', $deserialized->rpId);
    }

    #[Test]
    public function aCredentialRecordHasNoRpIdByDefault(): void
    {
        $credentialRecord = CredentialRecord::create(
            'credential-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        static::assertNull($credentialRecord->rpId);

        $json = $this->getSerializer()
            ->serialize($credentialRecord, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        static::assertStringNotContainsString('rpId', $json);
    }

    #[Test]
    public function aCredentialRecordSerializedBeforeTheRpIdMemberCanStillBeDeserialized(): void
    {
        $json = '{"publicKeyCredentialId":"Y3JlZGVudGlhbC1pZA","type":"public-key","transports":[],"attestationType":"none","trustPath":[],"aaguid":"00000000-0000-0000-0000-000000000000","credentialPublicKey":"cHVibGljLWtleS1kYXRh","userHandle":"dXNlci1oYW5kbGU","counter":10}';

        $deserialized = $this->getSerializer()
            ->deserialize($json, CredentialRecord::class, 'json');

        static::assertInstanceOf(CredentialRecord::class, $deserialized);
        static::assertNull($deserialized->rpId);
    }

    #[Test]
    public function publicKeyCredentialSourceExtendsCredentialRecord(): void
    {
        $credentialId = 'credential-id';
        $userHandle = 'user-handle';
        $counter = 10;
        $aaguid = Uuid::v4();
        $publicKey = 'public-key';

        $pkcs = new PublicKeyCredentialSource(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            $aaguid,
            $publicKey,
            $userHandle,
            $counter
        );

        // PublicKeyCredentialSource extends CredentialRecord
        static::assertInstanceOf(PublicKeyCredentialSource::class, $pkcs);
        static::assertInstanceOf(CredentialRecord::class, $pkcs);

        // It has the same properties (inherited from CredentialRecord)
        static::assertSame($credentialId, $pkcs->publicKeyCredentialId);
        static::assertSame($userHandle, $pkcs->userHandle);
        static::assertSame($counter, $pkcs->counter);
    }

    #[Test]
    public function credentialRecordCanGetPublicKeyCredentialDescriptor(): void
    {
        $credentialId = 'credential-id';
        $userHandle = 'user-handle';
        $counter = 10;
        $aaguid = Uuid::v4();
        $publicKey = 'public-key';
        $transports = ['usb', 'nfc'];

        $credentialRecord = CredentialRecord::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transports,
            'none',
            EmptyTrustPath::create(),
            $aaguid,
            $publicKey,
            $userHandle,
            $counter
        );

        $descriptor = $credentialRecord->getPublicKeyCredentialDescriptor();

        static::assertInstanceOf(PublicKeyCredentialDescriptor::class, $descriptor);
        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $descriptor->type);
        static::assertSame($credentialId, $descriptor->id);
        static::assertSame($transports, $descriptor->transports);
    }

    #[Test]
    public function credentialRecordCanGetAttestedCredentialData(): void
    {
        $credentialId = 'credential-id';
        $userHandle = 'user-handle';
        $counter = 10;
        $aaguid = Uuid::v4();
        $publicKey = 'public-key';

        $credentialRecord = CredentialRecord::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            $aaguid,
            $publicKey,
            $userHandle,
            $counter
        );

        $attestedCredentialData = $credentialRecord->getAttestedCredentialData();

        static::assertSame($aaguid, $attestedCredentialData->aaguid);
        static::assertSame($credentialId, $attestedCredentialData->credentialId);
        static::assertSame($publicKey, $attestedCredentialData->credentialPublicKey);
    }
}
