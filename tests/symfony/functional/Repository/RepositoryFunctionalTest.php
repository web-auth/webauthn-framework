<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Repository;

use function count;
use PHPUnit\Framework\Attributes\Test;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\Bundle\Functional\CredentialRecordRepository;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Functional tests for repository implementations in the Symfony bundle.
 *
 * @internal
 */
final class RepositoryFunctionalTest extends KernelTestCase
{
    private CacheItemPoolInterface $cache;

    protected function setUp(): void
    {
        $this->cache = new ArrayAdapter();
    }

    #[Test]
    public function publicKeyCredentialSourceRepositoryCanSaveAndRetrievePublicKeyCredentialSource(): void
    {
        // Given
        $repository = new PublicKeyCredentialSourceRepository($this->cache);

        $publicKeyCredentialSource = new PublicKeyCredentialSource(
            base64_decode('test123', true),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            base64_decode('testkey', true),
            'test-user',
            100
        );

        // When
        $repository->saveCredentialSource($publicKeyCredentialSource);
        $retrieved = $repository->findOneByCredentialId(base64_decode('test123', true));

        // Then - PublicKeyCredentialSource extends CredentialRecord, so it's both
        static::assertInstanceOf(CredentialRecord::class, $retrieved);
        static::assertInstanceOf(PublicKeyCredentialSource::class, $retrieved);
        static::assertSame('test-user', $retrieved->userHandle);
        static::assertSame(100, $retrieved->counter);
    }

    #[Test]
    public function publicKeyCredentialSourceRepositoryCanSaveAndRetrievePublicKeyCredentialSourceWrapper(): void
    {
        // Legacy CanSaveCredentialSource repositories only accept PublicKeyCredentialSource,
        // not arbitrary CredentialRecord — that is the BC contract restored for issue #832.
        $repository = new PublicKeyCredentialSourceRepository($this->cache);

        $publicKeyCredentialSource = new PublicKeyCredentialSource(
            base64_decode('test456', true),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            base64_decode('testkey2', true),
            'test-user-2',
            200
        );

        $repository->saveCredentialSource($publicKeyCredentialSource);
        $retrieved = $repository->findOneByCredentialId(base64_decode('test456', true));

        static::assertInstanceOf(CredentialRecord::class, $retrieved);
        static::assertInstanceOf(PublicKeyCredentialSource::class, $retrieved);
        static::assertSame('test-user-2', $retrieved->userHandle);
        static::assertSame(200, $retrieved->counter);
    }

    #[Test]
    public function credentialRecordRepositoryCanSaveAndRetrieveCredentialRecord(): void
    {
        // Given
        $repository = new CredentialRecordRepository($this->cache);

        $credentialRecord = CredentialRecord::create(
            'cr789',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            'testkey3',
            'test-user-3',
            300
        );

        // When
        $repository->saveCredentialRecord($credentialRecord);
        $retrieved = $repository->findOneByCredentialId('cr789');

        // Then
        static::assertInstanceOf(CredentialRecord::class, $retrieved);
        static::assertSame('test-user-3', $retrieved->userHandle);
        static::assertSame(300, $retrieved->counter);
    }

    #[Test]
    public function credentialRecordRepositoryCanSaveAndRetrievePublicKeyCredentialSource(): void
    {
        // Given
        $repository = new CredentialRecordRepository($this->cache);

        $publicKeyCredentialSource = new PublicKeyCredentialSource(
            base64_decode('pkcs999', true),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            base64_decode('testkey4', true),
            'test-user-4',
            400
        );

        // When
        $repository->saveCredentialRecord($publicKeyCredentialSource);
        $retrieved = $repository->findOneByCredentialId(base64_decode('pkcs999', true));

        // Then - PublicKeyCredentialSource extends CredentialRecord, so it's both
        static::assertInstanceOf(CredentialRecord::class, $retrieved);
        static::assertInstanceOf(PublicKeyCredentialSource::class, $retrieved);
        static::assertSame('test-user-4', $retrieved->userHandle);
        static::assertSame(400, $retrieved->counter);
    }

    #[Test]
    public function repositoryCanStoreBothTypesAndRetrieveThemForSameUser(): void
    {
        // Mixed types are only meaningful on a CanSaveCredentialRecord-style repository:
        // a legacy CanSaveCredentialSource repository contractually only accepts PublicKeyCredentialSource.
        $repository = new CredentialRecordRepository($this->cache);

        $userId = 'multi-user';

        $credentialRecord = CredentialRecord::create(
            'multi1',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            'multikey1',
            $userId,
            100
        );

        $publicKeyCredentialSource = new PublicKeyCredentialSource(
            'multi2',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            'multikey2',
            $userId,
            200
        );

        $repository->saveCredentialRecord($credentialRecord);
        $repository->saveCredentialRecord($publicKeyCredentialSource);

        $userEntity = PublicKeyCredentialUserEntity::create($userId, $userId, 'Multi User');
        $allCredentials = $repository->findAllForUserEntity($userEntity);

        // Then - should retrieve both types (all are CredentialRecord, some may also be PublicKeyCredentialSource)
        static::assertGreaterThanOrEqual(2, count($allCredentials));

        $hasCredentialRecord = false;
        $hasPublicKeyCredentialSource = false;

        foreach ($allCredentials as $credential) {
            static::assertInstanceOf(CredentialRecord::class, $credential);
            if ($credential->publicKeyCredentialId === 'multi1') {
                $hasCredentialRecord = true;
            }
            if ($credential instanceof PublicKeyCredentialSource && $credential->publicKeyCredentialId === 'multi2') {
                $hasPublicKeyCredentialSource = true;
            }
        }

        static::assertTrue($hasCredentialRecord, 'Should have CredentialRecord in results');
        static::assertTrue($hasPublicKeyCredentialSource, 'Should have PublicKeyCredentialSource in results');
    }

    #[Test]
    public function repositoryReturnsNullForNonExistentCredential(): void
    {
        // Given
        $repository = new PublicKeyCredentialSourceRepository($this->cache);

        // When
        $retrieved = $repository->findOneByCredentialId('non-existent');

        // Then
        static::assertNull($retrieved);
    }

    #[Test]
    public function repositoryReturnsEmptyArrayForUserWithNoCredentials(): void
    {
        // Given
        $repository = new PublicKeyCredentialSourceRepository($this->cache);
        $userEntity = PublicKeyCredentialUserEntity::create('no-creds-user', 'no-creds-user', 'No Creds User');

        // When
        $credentials = $repository->findAllForUserEntity($userEntity);

        // Then
        static::assertIsArray($credentials);
        static::assertEmpty($credentials);
    }

    #[Test]
    public function repositoryCanUpdateExistingCredential(): void
    {
        $repository = new CredentialRecordRepository($this->cache);

        $credentialId = 'update-test';

        $original = CredentialRecord::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            'originalkey',
            'update-user',
            100
        );

        $repository->saveCredentialRecord($original);

        $updated = CredentialRecord::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            'originalkey',
            'update-user',
            150
        );

        $repository->saveCredentialRecord($updated);

        $retrieved = $repository->findOneByCredentialId($credentialId);

        static::assertInstanceOf(CredentialRecord::class, $retrieved);
        static::assertSame(150, $retrieved->counter);
    }
}
