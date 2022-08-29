<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\DependencyInjection\Compiler\CounterCheckerSetterCompilerPass;
use Webauthn\Counter\CounterChecker;

/**
 * @internal
 */
final class CounterCheckerSetterCompilerPassTest extends AbstractCompilerPassTestCase
{
    /**
     * @test
     */
    public function theCounterCheckerIsCorrectlyAddedIfItExists(): void
    {
        //Given
        $this->setDefinition(AuthenticatorAssertionResponseValidator::class, new Definition());

        $this->setDefinition('counter_checker', new Definition());
        $this->container->setAlias(CounterChecker::class, 'counter_checker');

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            AuthenticatorAssertionResponseValidator::class,
            'setCounterChecker',
            [new Reference(CounterChecker::class)]
        );
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(
            new CounterCheckerSetterCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
    }
}
