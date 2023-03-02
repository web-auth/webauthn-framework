<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
use Webauthn\Bundle\DependencyInjection\Compiler\EnforcedSafetyNetApiKeyVerificationCompilerPass;

/**
 * @internal
 */
final class EnforcedSafetyNetApiKeyVerificationCompilerPassTest extends AbstractCompilerPassTestCase
{
    #[Test]
    public function androidSafetyNetApiVerificationIsEnabledWhenAllServicesAndParametersAreSet(): void
    {
        //Given
        $this->setDefinition(AndroidSafetyNetAttestationStatementSupport::class, new Definition());

        $this->setDefinition('http_client', new Definition());
        $this->container->setAlias('webauthn.android_safetynet.http_client', 'http_client');

        $this->setParameter('webauthn.android_safetynet.api_key', 'api_key');
        $this->setDefinition('request_factory', new Definition());
        $this->container->setAlias('webauthn.android_safetynet.request_factory', 'request_factory');

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            AndroidSafetyNetAttestationStatementSupport::class,
            'enableApiVerification',
            [
                new Reference('webauthn.android_safetynet.http_client'),
                'api_key',
                new Reference('webauthn.android_safetynet.request_factory'),
            ]
        );
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(
            new EnforcedSafetyNetApiKeyVerificationCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
    }
}
