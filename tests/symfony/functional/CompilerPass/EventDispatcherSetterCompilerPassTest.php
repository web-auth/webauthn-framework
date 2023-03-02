<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\Bundle\DependencyInjection\Compiler\EventDispatcherSetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\Service\DistantResourceMetadataService;
use Webauthn\MetadataService\Service\FidoAllianceCompliantMetadataService;
use Webauthn\MetadataService\Service\InMemoryMetadataService;
use Webauthn\MetadataService\Service\LocalResourceMetadataService;
use Webauthn\MetadataService\Service\StringMetadataService;

/**
 * @internal
 */
final class EventDispatcherSetterCompilerPassTest extends AbstractCompilerPassTestCase
{
    #[Test]
    #[DataProvider('getClassList')]
    public function eventDispatcherIsCorrectlySet(string $className): void
    {
        //Given
        $this->setDefinition('my_event_dispatcher', new Definition());
        $this->container->setAlias('webauthn.event_dispatcher', 'my_event_dispatcher');

        $definition = new Definition();
        $definition->addTag(EventDispatcherSetterCompilerPass::TAG);
        $this->setDefinition($className, $definition);

        //When
        $this->compile();

        //Then
        $this->assertContainerBuilderHasServiceDefinitionWithMethodCall(
            $className,
            'setEventDispatcher',
            [new Reference('webauthn.event_dispatcher')]
        );
    }

    public static function getClassList(): iterable
    {
        yield [PhpCertificateChainValidator::class];
        yield [DistantResourceMetadataService::class];
        yield [FidoAllianceCompliantMetadataService::class];
        yield [InMemoryMetadataService::class];
        yield [LocalResourceMetadataService::class];
        yield [StringMetadataService::class];
        yield [WebauthnExtension::class];
        yield [AndroidKeyAttestationStatementSupport::class];
        yield [AndroidSafetyNetAttestationStatementSupport::class];
        yield [AppleAttestationStatementSupport::class];
        yield [AttestationObjectLoader::class];
        yield [FidoU2FAttestationStatementSupport::class];
        yield [NoneAttestationStatementSupport::class];
        yield [PackedAttestationStatementSupport::class];
        yield [TPMAttestationStatementSupport::class];
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new EventDispatcherSetterCompilerPass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 0);
    }
}
