<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\Bundle\DependencyInjection\Compiler\ExtensionOutputCheckerCompilerPass;

/**
 * @internal
 */
final class ExtensionOutputCheckerCompilerPassTest extends AbstractCompilerPassTestCase
{
    #[Test]
    public function androidSafetyNetApiVerificationIsEnabledWhenAllServicesAndParametersAreSet(): void
    {
        //Given
        $this->setDefinition(ExtensionOutputCheckerHandler::class, new Definition());

        $extension1 = new Definition();
        $extension1->addTag(ExtensionOutputCheckerCompilerPass::TAG);
        $this->setDefinition('extension_1', $extension1);

        $extension2 = new Definition();
        $extension2->addTag(ExtensionOutputCheckerCompilerPass::TAG);
        $this->setDefinition('extension_2', $extension2);

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            ExtensionOutputCheckerHandler::class,
            'add',
            [new Reference('extension_1')]
        );
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            ExtensionOutputCheckerHandler::class,
            'add',
            [new Reference('extension_2')]
        );
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(
            new ExtensionOutputCheckerCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
    }
}
