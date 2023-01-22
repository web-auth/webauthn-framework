<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Controller\AssertionControllerFactory;
use Webauthn\Bundle\DependencyInjection\Compiler\LoggerSetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;
use Webauthn\Bundle\Security\Http\Authenticator\WebauthnAuthenticator;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\PublicKeyCredentialLoader;

/**
 * @internal
 */
final class LoggerSetterCompilerPassTest extends AbstractCompilerPassTestCase
{
    /**
     * @test
     * @dataProvider getClassList
     */
    public function loggerIsCorrectlySet(string $className): void
    {
        //Given
        $this->setDefinition('my_logger', new Definition());
        $this->container->setAlias('webauthn.logger', 'my_logger');

        $definition = new Definition();
        $definition->addTag(LoggerSetterCompilerPass::TAG);
        $this->setDefinition($className, $definition);

        //When
        $this->compile();

        //Then

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            $className,
            'setLogger',
            [new Reference('webauthn.logger')]
        );
    }

    public function getClassList(): iterable
    {
        yield [AssertionControllerFactory::class];
        yield [WebauthnExtension::class];
        yield [WebauthnAuthenticator::class];
        yield [AuthenticatorAssertionResponseValidator::class];
        yield [AuthenticatorAttestationResponseValidator::class];
        yield [PublicKeyCredentialLoader::class];
        yield [AttestationObjectLoader::class];
        yield [ThrowExceptionIfInvalid::class];
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new LoggerSetterCompilerPass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 0);
    }
}
