<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit;

use function array_filter;
use Doctrine\Bundle\DoctrineBundle\DoctrineBundle;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\LoadClassMetadataEventArgs;
use Doctrine\ORM\Mapping\ClassMetadata;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Bridge\Doctrine\DependencyInjection\CompilerPass\RegisterMappingsPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;
use Webauthn\Bundle\Doctrine\Type\AAGUIDDataType;
use Webauthn\Bundle\Doctrine\Type\AttestedCredentialDataType;
use Webauthn\Bundle\Doctrine\Type\Base64BinaryDataType;
use Webauthn\Bundle\Doctrine\Type\PublicKeyCredentialDescriptorType;
use Webauthn\Bundle\Doctrine\Type\TrustPathDataType;
use Webauthn\Bundle\Doctrine\UnmappedEntityListener;
use Webauthn\Bundle\WebauthnBundle;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Issue #1007: the Doctrine mapping provided by the bundle declared the signature counter as a signed 32-bit integer,
 * and an application extending `CredentialRecord` could not widen the column itself. That mapping only served
 * `DoctrineCredentialSourceRepository`. Both were deprecated and are removed in 6.0.0: applications map an entity of
 * their own and convert it from and to `CredentialRecord` in their repository.
 *
 * Such an entity declares its columns with the DBAL types of the bundle, which stay registered. An entity still
 * extending `CredentialRecord` or `PublicKeyCredentialEntity` without mapping their properties is refused: Doctrine
 * would only know its own properties, and a schema update would drop the columns of the credential records.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1007
 * @internal
 */
final class Issue1007RegressionTest extends TestCase
{
    private const REFUSAL = 'The entity "%s" extends "%s" without mapping its properties. The bundle no longer provides this mapping since 6.0.0: map an entity of your application and convert it from and to "%s" in your repository instead.';

    #[Test]
    public function theBundleRegistersNoDoctrineMapping(): void
    {
        // Given
        $container = new ContainerBuilder();

        // When
        (new WebauthnBundle())->build($container);

        // Then
        static::assertSame([], array_filter(
            $container->getCompilerPassConfig()
                ->getPasses(),
            static fn (object $pass): bool => $pass instanceof RegisterMappingsPass
        ));
    }

    #[Test]
    public function theDbalTypesOfTheBundleAreStillRegistered(): void
    {
        // Given
        $container = new ContainerBuilder();
        $container->setParameter('kernel.bundles', [
            'DoctrineBundle' => DoctrineBundle::class,
        ]);
        $container->prependExtensionConfig('doctrine', []);

        // When
        (new WebauthnExtension('webauthn'))->prepend($container);

        // Then
        static::assertSame([
            'attested_credential_data' => AttestedCredentialDataType::class,
            'aaguid' => AAGUIDDataType::class,
            'base64' => Base64BinaryDataType::class,
            'public_key_credential_descriptor' => PublicKeyCredentialDescriptorType::class,
            'trust_path' => TrustPathDataType::class,
        ], $container->getExtensionConfig('doctrine')[0]['dbal']['types'] ?? null);
    }

    #[Test]
    public function anEntityExtendingTheCredentialRecordWithoutMappingItIsRefused(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            sprintf(self::REFUSAL, Issue1007CredentialRecordEntity::class, CredentialRecord::class, CredentialRecord::class)
        );

        // When
        $this->loadClassMetadata(new ClassMetadata(Issue1007CredentialRecordEntity::class));
    }

    #[Test]
    public function anEntityExtendingTheUserEntityWithoutMappingItIsRefused(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage(
            sprintf(
                self::REFUSAL,
                Issue1007UserEntity::class,
                PublicKeyCredentialEntity::class,
                PublicKeyCredentialEntity::class
            )
        );

        // When
        $this->loadClassMetadata(new ClassMetadata(Issue1007UserEntity::class));
    }

    #[Test]
    public function anEntityMappingTheInheritedPropertiesIsAccepted(): void
    {
        // Given
        $credentialRecord = new ClassMetadata(Issue1007CredentialRecordEntity::class);
        $credentialRecord->mapField([
            'fieldName' => 'publicKeyCredentialId',
            'type' => Types::STRING,
        ]);
        $userEntity = new ClassMetadata(Issue1007UserEntity::class);
        $userEntity->mapField([
            'fieldName' => 'name',
            'type' => Types::STRING,
        ]);

        // When
        $this->loadClassMetadata($credentialRecord);
        $this->loadClassMetadata($userEntity);

        // Then
        $this->addToAssertionCount(1);
    }

    #[Test]
    public function aMappedSuperclassOfTheApplicationIsAccepted(): void
    {
        // Given
        $metadata = new ClassMetadata(Issue1007CredentialRecordEntity::class);
        $metadata->isMappedSuperclass = true;

        // When
        $this->loadClassMetadata($metadata);

        // Then
        $this->addToAssertionCount(1);
    }

    #[Test]
    public function anEntityOfTheApplicationIsAccepted(): void
    {
        // When
        $this->loadClassMetadata(new ClassMetadata(Issue1007ApplicationEntity::class));

        // Then
        $this->addToAssertionCount(1);
    }

    /**
     * @param ClassMetadata<object> $metadata
     */
    private function loadClassMetadata(ClassMetadata $metadata): void
    {
        (new UnmappedEntityListener())->loadClassMetadata(
            new LoadClassMetadataEventArgs($metadata, static::createStub(EntityManagerInterface::class))
        );
    }
}

/**
 * Mimics the entity documented up to 5.3: it extends the credential record and expects its columns from the bundle.
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
 * Mimics the entity now documented: it is converted from and to the credential record by the repository.
 *
 * @internal
 */
final class Issue1007ApplicationEntity
{
}
