<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\DependencyInjection\Compiler\CoseAlgorithmCompilerPass;

/**
 * @internal
 */
final class CoseAlgorithmCompilerPassTest extends AbstractCompilerPassTestCase
{
    /**
     * @test
     */
    public function coseAlgorithmsAreAddedToTHeAlgorithmManager(): void
    {
        //Given
        $this->setDefinition('webauthn.cose.algorithm.manager', new Definition());

        $algorithm1 = new Definition();
        $algorithm1->addTag(CoseAlgorithmCompilerPass::TAG);
        $this->setDefinition('algorithm_1', $algorithm1);

        $algorithm2 = new Definition();
        $algorithm2->addTag(CoseAlgorithmCompilerPass::TAG);
        $this->setDefinition('algorithm_2', $algorithm1);

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            'webauthn.cose.algorithm.manager',
            'add',
            [new Reference('algorithm_1')]
        );
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            'webauthn.cose.algorithm.manager',
            'add',
            [new Reference('algorithm_2')]
        );
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new CoseAlgorithmCompilerPass());
    }
}
