<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Repository;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use ReflectionClass;
use ReflectionMethod;
use ReflectionNamedType;
use Symfony\Component\Uid\Uuid;
use Webauthn\Bundle\Repository\CanSaveCredentialRecord;
use Webauthn\Bundle\Repository\CanSaveCredentialSource;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\DoctrineCredentialSourceRepository;
use Webauthn\Bundle\Repository\DummyCredentialRecordRepository;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Tests for bundle repository implementations to ensure they properly handle both
 * CredentialRecord and PublicKeyCredentialSource types (via inheritance).
 *
 * @internal
 */
final class RepositoryImplementationsTest extends TestCase
{
    #[Test]
    public function dummyCredentialRecordRepositoryImplementsCorrectInterfaces(): void
    {
        // Given
        $repository = new DummyCredentialRecordRepository(new NullLogger());

        // Then
        static::assertInstanceOf(CredentialRecordRepositoryInterface::class, $repository);
    }

    #[Test]
    public function dummyPublicKeyCredentialSourceRepositoryImplementsCorrectInterfaces(): void
    {
        // Given
        $repository = new DummyPublicKeyCredentialSourceRepository(new NullLogger());

        // Then
        static::assertInstanceOf(PublicKeyCredentialSourceRepositoryInterface::class, $repository);
    }

    #[Test]
    public function dummyCredentialRecordRepositoryReturnsCredentialRecord(): void
    {
        // Given
        $repository = new DummyCredentialRecordRepository(new NullLogger());

        // Then - verify the return type is CredentialRecord (nullable)
        $reflection = new ReflectionMethod($repository, 'findOneByCredentialId');
        $returnType = $reflection->getReturnType();

        static::assertInstanceOf(ReflectionNamedType::class, $returnType);
        static::assertSame(CredentialRecord::class, $returnType->getName());
        static::assertTrue($returnType->allowsNull());
    }

    #[Test]
    public function dummyPublicKeyCredentialSourceRepositoryReturnsCredentialRecord(): void
    {
        // Given
        $repository = new DummyPublicKeyCredentialSourceRepository(new NullLogger());

        // Then - verify the return type is CredentialRecord (nullable)
        $reflection = new ReflectionMethod($repository, 'findOneByCredentialId');
        $returnType = $reflection->getReturnType();

        static::assertInstanceOf(ReflectionNamedType::class, $returnType);
        static::assertSame(CredentialRecord::class, $returnType->getName());
        static::assertTrue($returnType->allowsNull());
    }

    #[Test]
    public function doctrineCredentialSourceRepositoryImplementsCorrectInterfaces(): void
    {
        // Given - use reflection to check class declaration instead of instantiating
        $reflection = new ReflectionClass(DoctrineCredentialSourceRepository::class);

        // Then
        static::assertTrue($reflection->implementsInterface(PublicKeyCredentialSourceRepositoryInterface::class));
        static::assertTrue($reflection->implementsInterface(CanSaveCredentialSource::class));
    }

    #[Test]
    public function doctrineCredentialSourceRepositoryAcceptsCredentialRecordInSaveMethod(): void
    {
        // Given - use reflection to check method signature
        $reflection = new ReflectionMethod(DoctrineCredentialSourceRepository::class, 'saveCredentialSource');
        $parameters = $reflection->getParameters();

        // Then - verify the parameter type accepts CredentialRecord
        static::assertCount(1, $parameters);
        $paramType = $parameters[0]->getType();

        static::assertInstanceOf(ReflectionNamedType::class, $paramType);
        static::assertSame(CredentialRecord::class, $paramType->getName());
    }

    #[Test]
    public function doctrineCredentialSourceRepositoryReturnsCredentialRecord(): void
    {
        // Given - use reflection to check method signature
        $reflection = new ReflectionMethod(DoctrineCredentialSourceRepository::class, 'findOneByCredentialId');
        $returnType = $reflection->getReturnType();

        // Then - verify the return type is CredentialRecord (nullable)
        static::assertInstanceOf(ReflectionNamedType::class, $returnType);
        static::assertSame(CredentialRecord::class, $returnType->getName());
        static::assertTrue($returnType->allowsNull());
    }

    #[Test]
    public function canSaveCredentialRecordInterfaceAcceptsCredentialRecord(): void
    {
        // This test verifies that the interface itself has the correct signature
        $reflection = new ReflectionMethod(CanSaveCredentialRecord::class, 'saveCredentialSource');
        $parameters = $reflection->getParameters();

        static::assertCount(1, $parameters);
        $paramType = $parameters[0]->getType();

        static::assertInstanceOf(ReflectionNamedType::class, $paramType);
        static::assertSame(CredentialRecord::class, $paramType->getName());
    }

    #[Test]
    public function canSaveCredentialSourceInterfaceExtendsCanSaveCredentialRecord(): void
    {
        // This test verifies that the deprecated interface extends the new one
        $reflection = new ReflectionClass(CanSaveCredentialSource::class);

        static::assertTrue($reflection->implementsInterface(CanSaveCredentialRecord::class));
    }

    #[Test]
    public function credentialRecordRepositoryInterfaceReturnsCredentialRecord(): void
    {
        // Verify findOneByCredentialId returns CredentialRecord (nullable)
        $reflection = new ReflectionMethod(CredentialRecordRepositoryInterface::class, 'findOneByCredentialId');
        $returnType = $reflection->getReturnType();

        static::assertInstanceOf(ReflectionNamedType::class, $returnType);
        static::assertSame(CredentialRecord::class, $returnType->getName());
        static::assertTrue($returnType->allowsNull());
    }

    #[Test]
    public function publicKeyCredentialSourceRepositoryInterfaceExtendsCredentialRecordRepositoryInterface(): void
    {
        // Verify the deprecated interface extends the new one
        $reflection = new ReflectionClass(PublicKeyCredentialSourceRepositoryInterface::class);

        static::assertTrue($reflection->implementsInterface(CredentialRecordRepositoryInterface::class));
    }

    #[Test]
    public function publicKeyCredentialSourceExtendsCredentialRecord(): void
    {
        // Verify inheritance relationship
        $reflection = new ReflectionClass(PublicKeyCredentialSource::class);

        static::assertTrue($reflection->isSubclassOf(CredentialRecord::class));
    }

    #[Test]
    public function repositoryCanStoreAndRetrieveBothTypes(): void
    {
        // Given - a mock repository that simulates real storage
        $storage = [];

        $repository = new class($storage) implements CredentialRecordRepositoryInterface, CanSaveCredentialRecord {
            public function __construct(
                private array &$storage
            ) {
            }

            public function saveCredentialSource(CredentialRecord $credentialRecord): void
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
            'user-1',
            10
        );

        $publicKeyCredentialSource = new PublicKeyCredentialSource(
            'pkcs-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key-2',
            'user-1',
            20
        );

        // When - saving both types (PublicKeyCredentialSource extends CredentialRecord)
        $repository->saveCredentialSource($credentialRecord);
        $repository->saveCredentialSource($publicKeyCredentialSource);

        // Then - both can be retrieved as CredentialRecord
        $retrievedCr = $repository->findOneByCredentialId('cr-id');
        $retrievedPkcs = $repository->findOneByCredentialId('pkcs-id');

        static::assertInstanceOf(CredentialRecord::class, $retrievedCr);
        static::assertInstanceOf(CredentialRecord::class, $retrievedPkcs);
        // PublicKeyCredentialSource is still a PublicKeyCredentialSource (inheritance)
        static::assertInstanceOf(PublicKeyCredentialSource::class, $retrievedPkcs);
        static::assertSame('user-1', $retrievedCr->userHandle);
        static::assertSame('user-1', $retrievedPkcs->userHandle);

        // And - findAllForUserEntity returns both
        $userEntity = PublicKeyCredentialUserEntity::create('user-1', 'user-1', 'User 1');
        $allCredentials = $repository->findAllForUserEntity($userEntity);

        static::assertCount(2, $allCredentials);
    }
}
