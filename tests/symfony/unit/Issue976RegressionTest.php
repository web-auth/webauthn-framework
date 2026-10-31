<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit;

use Doctrine\Bundle\DoctrineBundle\DependencyInjection\Compiler\DoctrineOrmMappingsPass;
use Doctrine\Deprecations\Deprecation;
use Doctrine\ORM\Mapping\Driver\XmlDriver;
use Doctrine\Persistence\Mapping\Driver\MappingDriverChain;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Webauthn\Bundle\WebauthnBundle;

/**
 * Issue #976: the bundle registered its Doctrine XML mapping with
 * `DoctrineOrmMappingsPass::createXmlMappingDriver($mappings, [], false, [], true)`, where the fourth argument is the
 * `$aliasMap` that DoctrineBundle 3.2 removed (namespace aliases are no longer supported by Doctrine). DoctrineBundle
 * 3.2.0 and 3.2.1 rejected that call with a TypeError, and DoctrineBundle 3.2.2 onwards triggers a deprecation on every
 * container build. The mapping must be registered without that argument while keeping the XSD validation of the
 * mapping files enabled, on every supported DoctrineBundle version.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/976
 * @see https://github.com/doctrine/DoctrineBundle/pull/2190
 * @internal
 */
final class Issue976RegressionTest extends TestCase
{
    private const ALIAS_MAP_DEPRECATION = 'https://github.com/doctrine/DoctrineBundle/pull/2190';

    #[Test]
    public function registeringTheDoctrineMappingTriggersNoAliasMapDeprecation(): void
    {
        Deprecation::enableTrackingDeprecations();
        $alreadyTriggered = Deprecation::getTriggeredDeprecations()[self::ALIAS_MAP_DEPRECATION] ?? 0;

        (new WebauthnBundle())->build(new ContainerBuilder());

        static::assertSame(
            $alreadyTriggered,
            Deprecation::getTriggeredDeprecations()[self::ALIAS_MAP_DEPRECATION] ?? 0,
            'The bundle still passes the $aliasMap argument removed in DoctrineBundle 3.2.'
        );
    }

    #[Test]
    public function theXmlMappingFilesAreStillValidatedAgainstTheDoctrineSchema(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('doctrine.default_entity_manager', 'default');
        $chainDriver = $container->register('doctrine.orm.default_metadata_driver', MappingDriverChain::class);

        $this->doctrineOrmMappingsPass()
            ->process($container);

        $methodCalls = $chainDriver->getMethodCalls();
        static::assertCount(1, $methodCalls);
        [$method, [$driver, $namespace]] = $methodCalls[0];
        static::assertSame('addDriver', $method);
        static::assertSame('Webauthn', $namespace);
        static::assertInstanceOf(Definition::class, $driver);
        static::assertSame(XmlDriver::class, $driver->getClass());
        static::assertTrue($driver->getArgument(2));
    }

    private function doctrineOrmMappingsPass(): DoctrineOrmMappingsPass
    {
        $container = new ContainerBuilder();
        (new WebauthnBundle())->build($container);

        foreach ($container->getCompilerPassConfig()->getBeforeOptimizationPasses() as $pass) {
            if ($pass instanceof DoctrineOrmMappingsPass) {
                return $pass;
            }
        }

        static::fail('The bundle does not register its Doctrine ORM mapping.');
    }
}
