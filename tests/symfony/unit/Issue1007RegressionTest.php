<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit;

use function array_filter;
use Doctrine\Bundle\DoctrineBundle\DoctrineBundle;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Bridge\Doctrine\DependencyInjection\CompilerPass\RegisterMappingsPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;
use Webauthn\Bundle\Doctrine\Type\AAGUIDDataType;
use Webauthn\Bundle\Doctrine\Type\AttestedCredentialDataType;
use Webauthn\Bundle\Doctrine\Type\Base64BinaryDataType;
use Webauthn\Bundle\Doctrine\Type\PublicKeyCredentialDescriptorType;
use Webauthn\Bundle\Doctrine\Type\TrustPathDataType;
use Webauthn\Bundle\WebauthnBundle;

/**
 * Issue #1007: the Doctrine mapping provided by the bundle declared the signature counter as a signed 32-bit integer,
 * and an application extending `CredentialRecord` could not widen the column itself. That mapping only served
 * `DoctrineCredentialSourceRepository`. Both were deprecated and are removed in 6.0.0: applications map an entity of
 * their own and convert it from and to `CredentialRecord` in their repository.
 *
 * Such an entity declares its columns with the DBAL types of the bundle, which stay registered.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1007
 * @internal
 */
final class Issue1007RegressionTest extends TestCase
{
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
}
