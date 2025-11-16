<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\Bundle\Repository\CanSaveCredentialRecord;
use Webauthn\Bundle\Repository\CanSaveCredentialSource;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class RepositoryCompatibilityTest extends AbstractTestCase
{
    #[Test]
    public function publicKeyCredentialSourceRepositoryCanHandleCredentialRecord(): void
    {
        $repository = new class() implements PublicKeyCredentialSourceRepositoryInterface, CanSaveCredentialSource {
            private array $storage = [];

            public function saveCredentialSource(CredentialRecord|PublicKeyCredentialSource $credentialRecord): void
            {
                $this->storage[$credentialRecord->publicKeyCredentialId] = $credentialRecord;
            }

            public function findOneByCredentialId(
                string $publicKeyCredentialId
            ): CredentialRecord|PublicKeyCredentialSource|null {
                return $this->storage[$publicKeyCredentialId] ?? null;
            }

            public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
            {
                return array_filter(
                    $this->storage,
                    fn ($credential) => $credential->userHandle === $publicKeyCredentialUserEntity->id
                );
            }
        };

        $credentialRecord = CredentialRecord::create(
            'test-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        // Should be able to save a CredentialRecord
        $repository->saveCredentialSource($credentialRecord);

        // Should be able to retrieve it
        $retrieved = $repository->findOneByCredentialId('test-id');
        static::assertInstanceOf(CredentialRecord::class, $retrieved);
        static::assertSame('test-id', $retrieved->publicKeyCredentialId);
    }

    #[Test]
    public function publicKeyCredentialSourceRepositoryCanHandlePublicKeyCredentialSource(): void
    {
        $repository = new class() implements PublicKeyCredentialSourceRepositoryInterface, CanSaveCredentialSource {
            private array $storage = [];

            public function saveCredentialSource(CredentialRecord|PublicKeyCredentialSource $credentialRecord): void
            {
                $this->storage[$credentialRecord->publicKeyCredentialId] = $credentialRecord;
            }

            public function findOneByCredentialId(
                string $publicKeyCredentialId
            ): CredentialRecord|PublicKeyCredentialSource|null {
                return $this->storage[$publicKeyCredentialId] ?? null;
            }

            public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
            {
                return array_filter(
                    $this->storage,
                    fn ($credential) => $credential->userHandle === $publicKeyCredentialUserEntity->id
                );
            }
        };

        $pkcs = PublicKeyCredentialSource::create(
            'test-id-2',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        // Should be able to save a PublicKeyCredentialSource
        $repository->saveCredentialSource($pkcs);

        // Should be able to retrieve it
        $retrieved = $repository->findOneByCredentialId('test-id-2');
        static::assertInstanceOf(PublicKeyCredentialSource::class, $retrieved);
        static::assertSame('test-id-2', $retrieved->publicKeyCredentialId);
    }

    #[Test]
    public function credentialRecordRepositoryCanHandleBothTypes(): void
    {
        $repository = new class() implements CredentialRecordRepositoryInterface, CanSaveCredentialRecord {
            private array $storage = [];

            public function saveCredentialSource(CredentialRecord|PublicKeyCredentialSource $credentialRecord): void
            {
                $this->storage[$credentialRecord->publicKeyCredentialId] = $credentialRecord;
            }

            public function findOneByCredentialId(
                string $publicKeyCredentialId
            ): CredentialRecord|PublicKeyCredentialSource|null {
                return $this->storage[$publicKeyCredentialId] ?? null;
            }

            public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
            {
                return array_filter(
                    $this->storage,
                    fn ($credential) => $credential->userHandle === $publicKeyCredentialUserEntity->id
                );
            }
        };

        $credentialRecord = CredentialRecord::create(
            'cr-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        $pkcs = PublicKeyCredentialSource::create(
            'pkcs-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key-2',
            'user-handle',
            20
        );

        // Should handle both types
        $repository->saveCredentialSource($credentialRecord);
        $repository->saveCredentialSource($pkcs);

        $retrievedCr = $repository->findOneByCredentialId('cr-id');
        $retrievedPkcs = $repository->findOneByCredentialId('pkcs-id');

        static::assertInstanceOf(CredentialRecord::class, $retrievedCr);
        static::assertInstanceOf(PublicKeyCredentialSource::class, $retrievedPkcs);
    }

    #[Test]
    public function repositoryImplementationCanStoreBothTypesInSameStorage(): void
    {
        // This test verifies that a single repository can handle both types
        $storage = [];

        $credentialRecord = CredentialRecord::create(
            'cr-1',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'key-1',
            'user-handle',
            10
        );

        $pkcs = PublicKeyCredentialSource::create(
            'pkcs-1',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'key-2',
            'user-handle',
            20
        );

        // Both types can be stored in the same array
        $storage[] = $credentialRecord;
        $storage[] = $pkcs;

        static::assertCount(2, $storage);
        static::assertInstanceOf(CredentialRecord::class, $storage[0]);
        static::assertInstanceOf(PublicKeyCredentialSource::class, $storage[1]);
        // PKCS and CR are independent classes
        static::assertNotInstanceOf(CredentialRecord::class, $storage[1]);
        static::assertNotInstanceOf(PublicKeyCredentialSource::class, $storage[0]);
    }

    #[Test]
    public function publicKeyCredentialSourceIsIndependentFromCredentialRecord(): void
    {
        $pkcs = PublicKeyCredentialSource::create(
            'test-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        $cr = CredentialRecord::create(
            'test-id-2',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key-2',
            'user-handle-2',
            20
        );

        // The two classes are independent
        static::assertInstanceOf(PublicKeyCredentialSource::class, $pkcs);
        static::assertNotInstanceOf(CredentialRecord::class, $pkcs);

        static::assertInstanceOf(CredentialRecord::class, $cr);
        static::assertNotInstanceOf(PublicKeyCredentialSource::class, $cr);
    }

    #[Test]
    public function bothRepositoryInterfacesAcceptUnionTypes(): void
    {
        // This test verifies that the type signatures are compatible
        $pkcsRepo = new class() implements PublicKeyCredentialSourceRepositoryInterface {
            public function findOneByCredentialId(
                string $publicKeyCredentialId
            ): CredentialRecord|PublicKeyCredentialSource|null {
                return null;
            }

            public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
            {
                return [];
            }
        };

        $crRepo = new class() implements CredentialRecordRepositoryInterface {
            public function findOneByCredentialId(
                string $publicKeyCredentialId
            ): CredentialRecord|PublicKeyCredentialSource|null {
                return null;
            }

            public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
            {
                return [];
            }
        };

        static::assertInstanceOf(PublicKeyCredentialSourceRepositoryInterface::class, $pkcsRepo);
        static::assertInstanceOf(CredentialRecordRepositoryInterface::class, $crRepo);
    }
}
