<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\Bundle\DependencyInjection\Compiler\AttestationStatementSupportCompilerPass;

/**
 * @internal
 */
final class AttestationStatementSupportCompilerPassTest extends AbstractCompilerPassTestCase
{
    /**
     * @test
     */
    public function aTaggedAttestationStatementSupportServiceIsAddedToTheManager(): void
    {
        //Given
        $this->setDefinition(AttestationStatementSupportManager::class, new Definition());

        $attestationStatementSupportService = new Definition();
        $attestationStatementSupportService->addTag(AttestationStatementSupportCompilerPass::TAG);
        $this->setDefinition('service_1', $attestationStatementSupportService);

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            AttestationStatementSupportManager::class,
            'add',
            [new Reference('service_1')]
        );
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(
            new AttestationStatementSupportCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
    }
}
