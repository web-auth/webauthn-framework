<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\DependencyInjection\Compiler\CertificateChainCheckerSetterCompilerPass;
use Webauthn\CertificateChainChecker\CertificateChainChecker;

/**
 * @internal
 */
final class CertificateChainCheckerSetterCompilerPassTest extends AbstractCompilerPassTestCase
{
    /**
     * @test
     */
    public function theCertificateChainCheckerIsSetToTheAuthenticatorAttestationResponseValidator(): void
    {
        //Given
        $this->setDefinition(AuthenticatorAttestationResponseValidator::class, new Definition());

        $this->setDefinition('certificate_chain_checker', new Definition());
        $this->container->setAlias(CertificateChainChecker::class, 'certificate_chain_checker');

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            AuthenticatorAttestationResponseValidator::class,
            'setCertificateChainChecker',
            [new Reference(CertificateChainChecker::class)]
        );
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(
            new CertificateChainCheckerSetterCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
    }
}
