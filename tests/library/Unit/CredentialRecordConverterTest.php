<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\Util\CredentialRecordConverter;

/**
 * @internal
 */
final class CredentialRecordConverterTest extends AbstractTestCase
{
    #[Test]
    public function canConvertPublicKeyCredentialSourceToCredentialRecord(): void
    {
        $credentialId = 'test-credential-id';
        $userHandle = 'test-user-handle';
        $counter = 42;
        $aaguid = Uuid::v4();
        $publicKey = 'test-public-key';
        $transports = ['usb', 'nfc'];

        $pkcs = new PublicKeyCredentialSource(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transports,
            'none',
            EmptyTrustPath::create(),
            $aaguid,
            $publicKey,
            $userHandle,
            $counter,
            [
                'custom' => 'data',
            ],
            true,
            false,
            true,
            'example.com'
        );

        $credentialRecord = CredentialRecordConverter::toCredentialRecord($pkcs);

        static::assertInstanceOf(CredentialRecord::class, $credentialRecord);
        static::assertSame($credentialId, $credentialRecord->publicKeyCredentialId);
        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $credentialRecord->type);
        static::assertSame($transports, $credentialRecord->transports);
        static::assertSame('none', $credentialRecord->attestationType);
        static::assertInstanceOf(EmptyTrustPath::class, $credentialRecord->trustPath);
        static::assertSame($aaguid, $credentialRecord->aaguid);
        static::assertSame($publicKey, $credentialRecord->credentialPublicKey);
        static::assertSame($userHandle, $credentialRecord->userHandle);
        static::assertSame($counter, $credentialRecord->counter);
        static::assertSame([
            'custom' => 'data',
        ], $credentialRecord->otherUI);
        static::assertTrue($credentialRecord->backupEligible);
        static::assertFalse($credentialRecord->backupStatus);
        static::assertTrue($credentialRecord->uvInitialized);
        static::assertSame('example.com', $credentialRecord->rpId);
    }

    #[Test]
    public function canConvertCredentialRecordToPublicKeyCredentialSource(): void
    {
        $credentialId = 'test-credential-id';
        $userHandle = 'test-user-handle';
        $counter = 42;
        $aaguid = Uuid::v4();
        $publicKey = 'test-public-key';
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
            [
                'custom' => 'data',
            ],
            true,
            false,
            true,
            'example.com'
        );

        $pkcs = CredentialRecordConverter::toPublicKeyCredentialSource($credentialRecord);

        static::assertInstanceOf(PublicKeyCredentialSource::class, $pkcs);
        static::assertSame($credentialId, $pkcs->publicKeyCredentialId);
        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $pkcs->type);
        static::assertSame($transports, $pkcs->transports);
        static::assertSame('none', $pkcs->attestationType);
        static::assertInstanceOf(EmptyTrustPath::class, $pkcs->trustPath);
        static::assertSame($aaguid, $pkcs->aaguid);
        static::assertSame($publicKey, $pkcs->credentialPublicKey);
        static::assertSame($userHandle, $pkcs->userHandle);
        static::assertSame($counter, $pkcs->counter);
        static::assertSame([
            'custom' => 'data',
        ], $pkcs->otherUI);
        static::assertTrue($pkcs->backupEligible);
        static::assertFalse($pkcs->backupStatus);
        static::assertTrue($pkcs->uvInitialized);
        static::assertSame('example.com', $pkcs->rpId);
    }

    #[Test]
    public function canConvertArrayOfPublicKeyCredentialSourcesToCredentialRecords(): void
    {
        $pkcs1 = new PublicKeyCredentialSource(
            'id1',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'key1',
            'user1',
            1
        );

        $pkcs2 = new PublicKeyCredentialSource(
            'id2',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'key2',
            'user2',
            2
        );

        $sources = [$pkcs1, $pkcs2];
        $records = CredentialRecordConverter::toCredentialRecords($sources);

        static::assertCount(2, $records);
        static::assertContainsOnlyInstancesOf(CredentialRecord::class, $records);
        static::assertSame('id1', $records[0]->publicKeyCredentialId);
        static::assertSame('id2', $records[1]->publicKeyCredentialId);
    }

    #[Test]
    public function canConvertArrayOfCredentialRecordsToPublicKeyCredentialSources(): void
    {
        $cr1 = CredentialRecord::create(
            'id1',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'key1',
            'user1',
            1
        );

        $cr2 = CredentialRecord::create(
            'id2',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'key2',
            'user2',
            2
        );

        $records = [$cr1, $cr2];
        $sources = CredentialRecordConverter::toPublicKeyCredentialSources($records);

        static::assertCount(2, $sources);
        static::assertContainsOnlyInstancesOf(PublicKeyCredentialSource::class, $sources);
        static::assertSame('id1', $sources[0]->publicKeyCredentialId);
        static::assertSame('id2', $sources[1]->publicKeyCredentialId);
    }

    #[Test]
    public function conversionPreservesAllData(): void
    {
        $credentialId = 'test-credential-id';
        $userHandle = 'test-user-handle';
        $counter = 99;
        $aaguid = Uuid::v4();
        $publicKey = 'test-public-key';
        $transports = ['usb', 'nfc', 'ble'];
        $otherUI = [
            'foo' => 'bar',
            'nested' => [
                'data' => 'value',
            ],
        ];

        // Create PKCS -> convert to CR -> convert back to PKCS
        $originalPkcs = new PublicKeyCredentialSource(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transports,
            'packed',
            EmptyTrustPath::create(),
            $aaguid,
            $publicKey,
            $userHandle,
            $counter,
            $otherUI,
            true,
            true,
            false
        );

        $credentialRecord = CredentialRecordConverter::toCredentialRecord($originalPkcs);
        $convertedPkcs = CredentialRecordConverter::toPublicKeyCredentialSource($credentialRecord);

        static::assertSame($originalPkcs->publicKeyCredentialId, $convertedPkcs->publicKeyCredentialId);
        static::assertSame($originalPkcs->type, $convertedPkcs->type);
        static::assertSame($originalPkcs->transports, $convertedPkcs->transports);
        static::assertSame($originalPkcs->attestationType, $convertedPkcs->attestationType);
        static::assertEquals($originalPkcs->trustPath, $convertedPkcs->trustPath);
        static::assertSame($originalPkcs->aaguid, $convertedPkcs->aaguid);
        static::assertSame($originalPkcs->credentialPublicKey, $convertedPkcs->credentialPublicKey);
        static::assertSame($originalPkcs->userHandle, $convertedPkcs->userHandle);
        static::assertSame($originalPkcs->counter, $convertedPkcs->counter);
        static::assertSame($originalPkcs->otherUI, $convertedPkcs->otherUI);
        static::assertSame($originalPkcs->backupEligible, $convertedPkcs->backupEligible);
        static::assertSame($originalPkcs->backupStatus, $convertedPkcs->backupStatus);
        static::assertSame($originalPkcs->uvInitialized, $convertedPkcs->uvInitialized);
    }

    #[Test]
    public function conversionHandlesNullValues(): void
    {
        $pkcs = new PublicKeyCredentialSource(
            'id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'key',
            'user',
            0
        );

        $credentialRecord = CredentialRecordConverter::toCredentialRecord($pkcs);

        static::assertNull($credentialRecord->otherUI);
        static::assertNull($credentialRecord->backupEligible);
        static::assertNull($credentialRecord->backupStatus);
        static::assertNull($credentialRecord->uvInitialized);

        $convertedPkcs = CredentialRecordConverter::toPublicKeyCredentialSource($credentialRecord);

        static::assertNull($convertedPkcs->otherUI);
        static::assertNull($convertedPkcs->backupEligible);
        static::assertNull($convertedPkcs->backupStatus);
        static::assertNull($convertedPkcs->uvInitialized);
    }
}
