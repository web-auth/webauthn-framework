<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Repository;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use ReflectionClass;
use ReflectionMethod;
use ReflectionNamedType;
use Webauthn\Bundle\Repository\CanSaveCredentialRecord;
use Webauthn\Bundle\Repository\CanSaveCredentialSource;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\DoctrineCredentialSourceRepository;
use Webauthn\Bundle\Repository\DummyCredentialRecordRepository;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialSource;

/**
 * Tests for bundle repository implementations to ensure they properly handle both
 * CredentialRecord and PublicKeyCredentialSource types (via inheritance).
 *
 * @internal
 */
final class RepositoryImplementationsTest extends TestCase
{
    #[Test]
    public function dummyCredentialRecordRepositoryImplementsNewInterface(): void
    {
        $repository = new DummyCredentialRecordRepository(new NullLogger());

        static::assertInstanceOf(CredentialRecordRepositoryInterface::class, $repository);
    }

    #[Test]
    public function dummyPublicKeyCredentialSourceRepositoryImplementsLegacyInterface(): void
    {
        $repository = new DummyPublicKeyCredentialSourceRepository(new NullLogger());

        static::assertInstanceOf(PublicKeyCredentialSourceRepositoryInterface::class, $repository);
        // Old interface extends new one, so the legacy dummy is also a CredentialRecordRepositoryInterface.
        static::assertInstanceOf(CredentialRecordRepositoryInterface::class, $repository);
    }

    #[Test]
    public function doctrineCredentialSourceRepositoryImplementsBothSaverInterfaces(): void
    {
        $reflection = new ReflectionClass(DoctrineCredentialSourceRepository::class);

        // BC: implements both interfaces so legacy subclasses overriding saveCredentialSource(PublicKeyCredentialSource)
        // keep working AND new code can call saveCredentialRecord(CredentialRecord).
        static::assertTrue($reflection->implementsInterface(PublicKeyCredentialSourceRepositoryInterface::class));
        static::assertTrue($reflection->implementsInterface(CanSaveCredentialSource::class));
        static::assertTrue($reflection->implementsInterface(CanSaveCredentialRecord::class));
    }

    #[Test]
    public function doctrineLegacySaveMethodKeeps52XSignature(): void
    {
        // Issue #832: subclasses overriding saveCredentialSource(PublicKeyCredentialSource) must keep compiling.
        $reflection = new ReflectionMethod(DoctrineCredentialSourceRepository::class, 'saveCredentialSource');
        $parameters = $reflection->getParameters();

        static::assertCount(1, $parameters);
        $paramType = $parameters[0]->getType();

        static::assertInstanceOf(ReflectionNamedType::class, $paramType);
        static::assertSame(PublicKeyCredentialSource::class, $paramType->getName());
    }

    #[Test]
    public function doctrineNewSaveMethodAcceptsCredentialRecord(): void
    {
        $reflection = new ReflectionMethod(DoctrineCredentialSourceRepository::class, 'saveCredentialRecord');
        $parameters = $reflection->getParameters();

        static::assertCount(1, $parameters);
        $paramType = $parameters[0]->getType();

        static::assertInstanceOf(ReflectionNamedType::class, $paramType);
        static::assertSame(CredentialRecord::class, $paramType->getName());
    }

    #[Test]
    public function newSaverInterfaceUsesNewMethodName(): void
    {
        $reflection = new ReflectionMethod(CanSaveCredentialRecord::class, 'saveCredentialRecord');
        $parameters = $reflection->getParameters();

        static::assertCount(1, $parameters);
        $paramType = $parameters[0]->getType();

        static::assertInstanceOf(ReflectionNamedType::class, $paramType);
        static::assertSame(CredentialRecord::class, $paramType->getName());
    }

    #[Test]
    public function legacySaverInterfaceKeepsOldSignature(): void
    {
        $reflection = new ReflectionMethod(CanSaveCredentialSource::class, 'saveCredentialSource');
        $parameters = $reflection->getParameters();

        static::assertCount(1, $parameters);
        $paramType = $parameters[0]->getType();

        static::assertInstanceOf(ReflectionNamedType::class, $paramType);
        static::assertSame(PublicKeyCredentialSource::class, $paramType->getName());
    }

    #[Test]
    public function legacySaverInterfaceDoesNotExtendNewOne(): void
    {
        // Otherwise legacy implementations would be forced to also declare saveCredentialRecord().
        $reflection = new ReflectionClass(CanSaveCredentialSource::class);

        static::assertFalse($reflection->implementsInterface(CanSaveCredentialRecord::class));
    }

    #[Test]
    public function publicKeyCredentialSourceRepositoryInterfaceExtendsCredentialRecordRepositoryInterface(): void
    {
        $reflection = new ReflectionClass(PublicKeyCredentialSourceRepositoryInterface::class);

        static::assertTrue($reflection->implementsInterface(CredentialRecordRepositoryInterface::class));
    }

    #[Test]
    public function publicKeyCredentialSourceExtendsCredentialRecord(): void
    {
        $reflection = new ReflectionClass(PublicKeyCredentialSource::class);

        static::assertTrue($reflection->isSubclassOf(CredentialRecord::class));
    }
}
