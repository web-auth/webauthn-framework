<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\DependencyInjection\Compiler\LoggerSetterCompilerPass;
use Webauthn\PublicKeyCredentialLoader;

/**
 * @internal
 */
final class LoggerSetterCompilerPassTest extends AbstractCompilerPassTestCase
{
    /**
     * @test
     */
    public function androidSafetyNetApiVerificationIsEnabledWhenAllServicesAndParametersAreSet(): void
    {
        //Given
        $this->setDefinition('my_logger', new Definition());
        $this->container->setAlias('webauthn.logger', 'my_logger');

        $this->setDefinition(AuthenticatorAssertionResponseValidator::class, new Definition());
        $this->setDefinition(AuthenticatorAttestationResponseValidator::class, new Definition());
        $this->setDefinition(PublicKeyCredentialLoader::class, new Definition());
        $this->setDefinition(AttestationObjectLoader::class, new Definition());

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            AuthenticatorAssertionResponseValidator::class,
            'setLogger',
            [new Reference('webauthn.logger')]
        );
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            AuthenticatorAttestationResponseValidator::class,
            'setLogger',
            [new Reference('webauthn.logger')]
        );
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            PublicKeyCredentialLoader::class,
            'setLogger',
            [new Reference('webauthn.logger')]
        );
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            AttestationObjectLoader::class,
            'setLogger',
            [new Reference('webauthn.logger')]
        );
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new LoggerSetterCompilerPass());
    }
}
