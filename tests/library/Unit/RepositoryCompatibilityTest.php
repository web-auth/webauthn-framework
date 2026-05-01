<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
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
    public function legacyRepositoryStoresPublicKeyCredentialSource(): void
    {
        // 5.2.x-style repository: implements only the deprecated interfaces and only accepts
        // PublicKeyCredentialSource — that signature must keep working under the BC promise.
        $repository = new class() implements PublicKeyCredentialSourceRepositoryInterface, CanSaveCredentialSource {
            /**
             * @var array<string, PublicKeyCredentialSource>
             */
            private array $storage = [];

            public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
            {
                $this->storage[$publicKeyCredentialSource->publicKeyCredentialId] = $publicKeyCredentialSource;
            }

            public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
            {
                return $this->storage[$publicKeyCredentialId] ?? null;
            }

            public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
            {
                return array_filter(
                    $this->storage,
                    static fn (CredentialRecord $credential): bool => $credential->userHandle === $publicKeyCredentialUserEntity->id
                );
            }
        };

        $pkcs = new PublicKeyCredentialSource(
            'legacy-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        $repository->saveCredentialSource($pkcs);

        $retrieved = $repository->findOneByCredentialId('legacy-id');
        static::assertInstanceOf(PublicKeyCredentialSource::class, $retrieved);
        static::assertSame('legacy-id', $retrieved->publicKeyCredentialId);
    }

    #[Test]
    public function newRepositoryStoresAnyCredentialRecord(): void
    {
        // New 5.3 repository: implements only the new interfaces with the new method name,
        // and accepts both raw CredentialRecord and PublicKeyCredentialSource (since PKCS extends CR).
        $repository = new class() implements CredentialRecordRepositoryInterface, CanSaveCredentialRecord {
            /**
             * @var array<string, CredentialRecord>
             */
            private array $storage = [];

            public function saveCredentialRecord(CredentialRecord $credentialRecord): void
            {
                $this->storage[$credentialRecord->publicKeyCredentialId] = $credentialRecord;
            }

            public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
            {
                return $this->storage[$publicKeyCredentialId] ?? null;
            }

            public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
            {
                return array_filter(
                    $this->storage,
                    static fn (CredentialRecord $credential): bool => $credential->userHandle === $publicKeyCredentialUserEntity->id
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

        $pkcs = new PublicKeyCredentialSource(
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

        $repository->saveCredentialRecord($credentialRecord);
        $repository->saveCredentialRecord($pkcs);

        static::assertInstanceOf(CredentialRecord::class, $repository->findOneByCredentialId('cr-id'));
        static::assertInstanceOf(PublicKeyCredentialSource::class, $repository->findOneByCredentialId('pkcs-id'));
    }

    #[Test]
    public function publicKeyCredentialSourceExtendsCredentialRecord(): void
    {
        $pkcs = new PublicKeyCredentialSource(
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

        static::assertInstanceOf(CredentialRecord::class, $pkcs);
        static::assertNotInstanceOf(PublicKeyCredentialSource::class, $cr);
    }

    #[Test]
    public function deprecatedRepositoryInterfaceExtendsNewOne(): void
    {
        // Composer-level guarantee: a 5.2 repository injected where the bundle now requires
        // CredentialRecordRepositoryInterface still satisfies the type-hint.
        $pkcsRepo = new class() implements PublicKeyCredentialSourceRepositoryInterface {
            public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
            {
                return null;
            }

            public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
            {
                return [];
            }
        };

        static::assertInstanceOf(CredentialRecordRepositoryInterface::class, $pkcsRepo);
    }

    #[Test]
    public function deprecatedSaverInterfaceIsIndependentFromNewOne(): void
    {
        // Implementing CanSaveCredentialSource alone must NOT force implementing the new
        // CanSaveCredentialRecord — that was the LSP trap fixed for issue #832.
        static::assertFalse(
            (new ReflectionClass(CanSaveCredentialSource::class))
                ->implementsInterface(CanSaveCredentialRecord::class)
        );
    }
}
