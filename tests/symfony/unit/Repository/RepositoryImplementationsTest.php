<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Repository;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use ReflectionClass;
use ReflectionMethod;
use ReflectionUnionType;
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
 * CredentialRecord and PublicKeyCredentialSource types.
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
    public function dummyCredentialRecordRepositoryReturnsCorrectUnionType(): void
    {
        // Given
        $repository = new DummyCredentialRecordRepository(new NullLogger());

        // Then - verify the return type is the correct union type
        $reflection = new ReflectionMethod($repository, 'findOneByCredentialId');
        $returnType = $reflection->getReturnType();

        static::assertInstanceOf(ReflectionUnionType::class, $returnType);

        $types = array_map(fn ($type) => $type->getName(), $returnType->getTypes());
        static::assertContains(CredentialRecord::class, $types);
        static::assertContains(PublicKeyCredentialSource::class, $types);
        static::assertTrue($returnType->allowsNull());
    }

    #[Test]
    public function dummyPublicKeyCredentialSourceRepositoryReturnsCorrectUnionType(): void
    {
        // Given
        $repository = new DummyPublicKeyCredentialSourceRepository(new NullLogger());

        // Then - verify the return type is the correct union type
        $reflection = new ReflectionMethod($repository, 'findOneByCredentialId');
        $returnType = $reflection->getReturnType();

        static::assertInstanceOf(ReflectionUnionType::class, $returnType);

        $types = array_map(fn ($type) => $type->getName(), $returnType->getTypes());
        static::assertContains(CredentialRecord::class, $types);
        static::assertContains(PublicKeyCredentialSource::class, $types);
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
    public function doctrineCredentialSourceRepositoryAcceptsUnionTypeInSaveMethod(): void
    {
        // Given - use reflection to check method signature
        $reflection = new ReflectionMethod(DoctrineCredentialSourceRepository::class, 'saveCredentialSource');
        $parameters = $reflection->getParameters();

        // Then - verify the parameter type accepts union type
        static::assertCount(1, $parameters);
        $paramType = $parameters[0]->getType();

        static::assertInstanceOf(ReflectionUnionType::class, $paramType);

        $types = array_map(fn ($type) => $type->getName(), $paramType->getTypes());
        static::assertContains(CredentialRecord::class, $types);
        static::assertContains(PublicKeyCredentialSource::class, $types);
    }

    #[Test]
    public function doctrineCredentialSourceRepositoryReturnsCorrectUnionType(): void
    {
        // Given - use reflection to check method signature
        $reflection = new ReflectionMethod(DoctrineCredentialSourceRepository::class, 'findOneByCredentialId');
        $returnType = $reflection->getReturnType();

        // Then - verify the return type is the correct union type
        static::assertInstanceOf(ReflectionUnionType::class, $returnType);

        $types = array_map(fn ($type) => $type->getName(), $returnType->getTypes());
        static::assertContains(CredentialRecord::class, $types);
        static::assertContains(PublicKeyCredentialSource::class, $types);
        static::assertTrue($returnType->allowsNull());
    }

    #[Test]
    public function canSaveCredentialRecordInterfaceAcceptsUnionType(): void
    {
        // This test verifies that the interface itself has the correct signature
        $reflection = new ReflectionMethod(CanSaveCredentialRecord::class, 'saveCredentialSource');
        $parameters = $reflection->getParameters();

        static::assertCount(1, $parameters);
        $paramType = $parameters[0]->getType();

        static::assertInstanceOf(ReflectionUnionType::class, $paramType);

        $types = array_map(fn ($type) => $type->getName(), $paramType->getTypes());
        static::assertContains(CredentialRecord::class, $types);
        static::assertContains(PublicKeyCredentialSource::class, $types);
    }

    #[Test]
    public function canSaveCredentialSourceInterfaceAcceptsUnionType(): void
    {
        // This test verifies that the deprecated interface has the correct signature
        $reflection = new ReflectionMethod(CanSaveCredentialSource::class, 'saveCredentialSource');
        $parameters = $reflection->getParameters();

        static::assertCount(1, $parameters);
        $paramType = $parameters[0]->getType();

        static::assertInstanceOf(ReflectionUnionType::class, $paramType);

        $types = array_map(fn ($type) => $type->getName(), $paramType->getTypes());
        static::assertContains(CredentialRecord::class, $types);
        static::assertContains(PublicKeyCredentialSource::class, $types);
    }

    #[Test]
    public function credentialRecordRepositoryInterfaceReturnsUnionType(): void
    {
        // Verify findOneByCredentialId returns union type
        $reflection = new ReflectionMethod(CredentialRecordRepositoryInterface::class, 'findOneByCredentialId');
        $returnType = $reflection->getReturnType();

        static::assertInstanceOf(ReflectionUnionType::class, $returnType);

        $types = array_map(fn ($type) => $type->getName(), $returnType->getTypes());
        static::assertContains(CredentialRecord::class, $types);
        static::assertContains(PublicKeyCredentialSource::class, $types);
        static::assertTrue($returnType->allowsNull());
    }

    #[Test]
    public function publicKeyCredentialSourceRepositoryInterfaceReturnsUnionType(): void
    {
        // Verify findOneByCredentialId returns union type
        $reflection = new ReflectionMethod(
            PublicKeyCredentialSourceRepositoryInterface::class,
            'findOneByCredentialId'
        );
        $returnType = $reflection->getReturnType();

        static::assertInstanceOf(ReflectionUnionType::class, $returnType);

        $types = array_map(fn ($type) => $type->getName(), $returnType->getTypes());
        static::assertContains(CredentialRecord::class, $types);
        static::assertContains(PublicKeyCredentialSource::class, $types);
        static::assertTrue($returnType->allowsNull());
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
            'user-1',
            10
        );

        $publicKeyCredentialSource = PublicKeyCredentialSource::create(
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

        // When - saving both types
        $repository->saveCredentialSource($credentialRecord);
        $repository->saveCredentialSource($publicKeyCredentialSource);

        // Then - both can be retrieved
        $retrievedCr = $repository->findOneByCredentialId('cr-id');
        $retrievedPkcs = $repository->findOneByCredentialId('pkcs-id');

        static::assertInstanceOf(CredentialRecord::class, $retrievedCr);
        static::assertInstanceOf(PublicKeyCredentialSource::class, $retrievedPkcs);
        static::assertSame('user-1', $retrievedCr->userHandle);
        static::assertSame('user-1', $retrievedPkcs->userHandle);

        // And - findAllForUserEntity returns both
        $userEntity = PublicKeyCredentialUserEntity::create('user-1', 'user-1', 'User 1');
        $allCredentials = $repository->findAllForUserEntity($userEntity);

        static::assertCount(2, $allCredentials);
    }
}
