<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\LoadClassMetadataEventArgs;
use Doctrine\ORM\Mapping\ClassMetadata;
use const E_USER_DEPRECATED;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use Webauthn\Bundle\Doctrine\DeprecatedMappingListener;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialEntity;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Issue #1007: the Doctrine mapping provided by the bundle declared the signature counter as a signed 32-bit integer,
 * while the authenticators send an unsigned 32-bit value. An application extending `CredentialRecord` cannot widen the
 * column itself: Doctrine ORM 3 refuses an attribute override changing the type of an inherited field, and the
 * `unsigned` option is ignored by PostgreSQL.
 *
 * That mapping only served `DoctrineCredentialSourceRepository`, deprecated since 5.2.0: applications are expected to
 * map an entity of their own. The bundle reports the entities still relying on it, and only those.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1007
 * @internal
 */
final class Issue1007RegressionTest extends TestCase
{
    private const DEPRECATION = 'Since web-auth/webauthn-symfony-bundle 5.4.0: The entity "%s" extends "%s" and relies on the Doctrine mapping provided by the bundle. This mapping is deprecated and will be removed in 6.0.0. Map an entity of your application and convert it from and to "%s" in your repository instead.';

    #[Test]
    public function anEntityExtendingTheCredentialRecordIsReported(): void
    {
        // When
        $deprecations = $this->collectDeprecations(Issue1007CredentialRecordEntity::class);

        // Then
        static::assertSame([
            sprintf(
                self::DEPRECATION,
                Issue1007CredentialRecordEntity::class,
                CredentialRecord::class,
                CredentialRecord::class
            ),
        ], $deprecations);
    }

    /**
     * `PublicKeyCredentialUserEntity` extends `PublicKeyCredentialEntity`, which the bundle maps too. The entity is
     * reported once, with the class it actually extends.
     */
    #[Test]
    public function anEntityExtendingTheUserEntityIsReportedOnceWithTheUserEntityName(): void
    {
        // When
        $deprecations = $this->collectDeprecations(Issue1007UserEntity::class);

        // Then
        static::assertSame([
            sprintf(
                self::DEPRECATION,
                Issue1007UserEntity::class,
                PublicKeyCredentialUserEntity::class,
                PublicKeyCredentialUserEntity::class
            ),
        ], $deprecations);
    }

    #[Test]
    public function anEntityExtendingAnotherMappedEntityIsReported(): void
    {
        // When
        $deprecations = $this->collectDeprecations(Issue1007RpEntity::class);

        // Then
        static::assertSame([
            sprintf(
                self::DEPRECATION,
                Issue1007RpEntity::class,
                PublicKeyCredentialEntity::class,
                PublicKeyCredentialEntity::class
            ),
        ], $deprecations);
    }

    #[Test]
    public function anEntityOfTheApplicationIsNotReported(): void
    {
        // When
        $deprecations = $this->collectDeprecations(Issue1007ApplicationEntity::class);

        // Then
        static::assertSame([], $deprecations);
    }

    /**
     * `PublicKeyCredentialUserEntity` is a mapped superclass of the bundle extending another one,
     * `PublicKeyCredentialEntity`: loading its metadata is not the doing of the application.
     */
    #[Test]
    public function theMappedSuperclassesOfTheBundleAreNotReported(): void
    {
        // When
        $deprecations = [
            ...$this->collectDeprecations(CredentialRecord::class, true),
            ...$this->collectDeprecations(PublicKeyCredentialUserEntity::class, true),
        ];

        // Then
        static::assertSame([], $deprecations);
    }

    /**
     * @param class-string $className
     * @return list<string>
     */
    private function collectDeprecations(string $className, bool $isMappedSuperclass = false): array
    {
        $deprecations = [];
        set_error_handler(static function (int $level, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_USER_DEPRECATED);
        try {
            $this->loadClassMetadata($className, $isMappedSuperclass);
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }

    /**
     * @param class-string $className
     */
    private function loadClassMetadata(string $className, bool $isMappedSuperclass = false): void
    {
        $metadata = new ClassMetadata($className);
        $metadata->isMappedSuperclass = $isMappedSuperclass;

        (new DeprecatedMappingListener())->loadClassMetadata(
            new LoadClassMetadataEventArgs($metadata, static::createStub(EntityManagerInterface::class))
        );
    }
}

/**
 * Mimics the entity documented up to 5.3: it extends the credential record and gets its columns from the bundle.
 *
 * @internal
 */
final class Issue1007CredentialRecordEntity extends CredentialRecord
{
}

/**
 * @internal
 */
final class Issue1007UserEntity extends PublicKeyCredentialUserEntity
{
}

/**
 * @internal
 */
final class Issue1007RpEntity extends PublicKeyCredentialRpEntity
{
}

/**
 * Mimics the entity now documented: it is converted from and to the credential record by the repository.
 *
 * @internal
 */
final class Issue1007ApplicationEntity
{
}
