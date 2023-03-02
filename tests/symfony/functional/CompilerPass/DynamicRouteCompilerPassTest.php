<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\Routing\Loader;

/**
 * @internal
 */
final class DynamicRouteCompilerPassTest extends AbstractCompilerPassTestCase
{
    #[Test]
    public function dynamicRoutesAreAddedToTheLoader(): void
    {
        //Given
        $this->setDefinition(Loader::class, new Definition());

        $route1 = new Definition();
        $route1->addTag(DynamicRouteCompilerPass::TAG, [
            'path' => '/foo/bar',
            'host' => null,
        ]);
        $this->setDefinition('route_1', $route1);

        $route2 = new Definition();
        $route2->addTag(DynamicRouteCompilerPass::TAG, [
            'path' => '/{id}/enable',
            'host' => 'www.foo.bar',
            'method' => 'GET',
        ]);
        $this->setDefinition('route_2', $route2);

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            Loader::class,
            'add',
            ['/foo/bar', null, 'route_1', 'POST']
        );
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            Loader::class,
            'add',
            ['/{id}/enable', 'www.foo.bar', 'route_2', 'GET']
        );
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new DynamicRouteCompilerPass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 0);
    }
}
