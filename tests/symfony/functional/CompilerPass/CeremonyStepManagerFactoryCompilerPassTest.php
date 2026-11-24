<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use function array_slice;
use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\DependencyInjection\Compiler\CeremonyStepManagerFactoryCompilerPass;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\StatusReportRepository;

/**
 * @see https://github.com/web-auth/webauthn-framework/issues/1002
 * @internal
 */
final class CeremonyStepManagerFactoryCompilerPassTest extends AbstractCompilerPassTestCase
{
    #[Test]
    public function theFactoryRequiresAStatementWhenTheBundleDoesNotSayOtherwise(): void
    {
        $this->registerMetadataServices();

        $this->compile();

        static::assertTrue($this->requireStatementArgument());
    }

    #[Test]
    public function theFactoryReceivesTheRequirementOfAStatementFromTheBundleConfiguration(): void
    {
        $this->registerMetadataServices();
        $this->setParameter('webauthn.metadata.require_statement', false);

        $this->compile();

        static::assertSame('%webauthn.metadata.require_statement%', $this->requireStatementArgument());
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(
            new CeremonyStepManagerFactoryCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
    }

    /**
     * The constraint of assertContainerBuilderHasServiceDefinitionWithMethodCall() compares the arguments loosely,
     * where a placeholder equals true.
     */
    private function requireStatementArgument(): mixed
    {
        $methodCalls = $this->container->findDefinition(CeremonyStepManagerFactory::class)->getMethodCalls();
        static::assertCount(1, $methodCalls);
        [$method, $arguments] = $methodCalls[0];
        static::assertSame('enableMetadataStatementSupport', $method);
        static::assertEquals([
            new Reference(MetadataStatementRepository::class),
            new Reference(StatusReportRepository::class),
            new Reference(CertificateChainValidator::class),
        ], array_slice($arguments, 0, 3));
        static::assertCount(4, $arguments);

        return $arguments[3];
    }

    private function registerMetadataServices(): void
    {
        $this->setDefinition(CeremonyStepManagerFactory::class, new Definition(CeremonyStepManagerFactory::class));
        $this->setDefinition('app.metadata_statement_repository', new Definition());
        $this->setDefinition('app.status_report_repository', new Definition());
        $this->setDefinition('app.certificate_chain_validator', new Definition());
        $this->container->setAlias(MetadataStatementRepository::class, 'app.metadata_statement_repository');
        $this->container->setAlias(StatusReportRepository::class, 'app.status_report_repository');
        $this->container->setAlias(CertificateChainValidator::class, 'app.certificate_chain_validator');
    }
}
