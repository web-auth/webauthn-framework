<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\CompilerPass;

use function class_exists;
use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractCompilerPassTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\Compiler\CheckAliasValidityPass;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Webauthn\Bundle\DependencyInjection\Compiler\PublicKeyCredentialSourceRepositoryAliasCompilerPass;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Tests\Bundle\Functional\CredentialRecordRepository;
use Webauthn\Tests\Bundle\Functional\PublicKeyCredentialSourceRepository;

/**
 * Issue #938: the deprecated interface is aliased to the configured credential repository. Symfony refuses an
 * interface alias whose target does not implement it, so the alias must be dropped for repositories that only
 * implement CredentialRecordRepositoryInterface. CheckAliasValidityPass only exists since Symfony 7.1, hence the
 * conditional registration.
 *
 * @internal
 */
final class PublicKeyCredentialSourceRepositoryAliasCompilerPassTest extends AbstractCompilerPassTestCase
{
    #[Test]
    public function theDeprecatedAliasIsKeptWhenTheRepositoryImplementsTheDeprecatedInterface(): void
    {
        // Given
        $this->registerRepository(PublicKeyCredentialSourceRepository::class);

        // When
        $this->compile();

        // Then
        static::assertTrue($this->container->hasAlias(PublicKeyCredentialSourceRepositoryInterface::class));
        static::assertSame(
            'credential_repository',
            (string) $this->container->getAlias(PublicKeyCredentialSourceRepositoryInterface::class)
        );
    }

    #[Test]
    public function theDeprecatedAliasIsRemovedWhenTheRepositoryDoesNotImplementTheDeprecatedInterface(): void
    {
        // Given
        $this->registerRepository(CredentialRecordRepository::class);

        // When
        $this->compile();

        // Then
        static::assertFalse($this->container->hasAlias(PublicKeyCredentialSourceRepositoryInterface::class));
        static::assertTrue($this->container->hasAlias(CredentialRecordRepositoryInterface::class));
    }

    #[Test]
    public function theDeprecatedAliasIsKeptWhenTheTargetClassCannotBeDetermined(): void
    {
        // Given
        $definition = new Definition();
        $definition->setPublic(true);
        $definition->setFactory([PublicKeyCredentialSourceRepository::class, 'create']);
        $this->setDefinition('credential_repository', $definition);
        $this->container->setAlias(PublicKeyCredentialSourceRepositoryInterface::class, 'credential_repository')
            ->setPublic(true);

        // When
        $this->compile();

        // Then
        static::assertTrue($this->container->hasAlias(PublicKeyCredentialSourceRepositoryInterface::class));
    }

    protected function registerCompilerPass(ContainerBuilder $container): void
    {
        $container->addCompilerPass(
            new PublicKeyCredentialSourceRepositoryAliasCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
        if (class_exists(CheckAliasValidityPass::class)) {
            $container->addCompilerPass(new CheckAliasValidityPass(), PassConfig::TYPE_BEFORE_REMOVING, -100);
        }
    }

    private function registerRepository(string $class): void
    {
        $definition = new Definition($class);
        $definition->setPublic(true);
        $definition->setSynthetic(true);
        $this->setDefinition('credential_repository', $definition);

        $this->container->setAlias(CredentialRecordRepositoryInterface::class, 'credential_repository')
            ->setPublic(true);
        $this->container->setAlias(PublicKeyCredentialSourceRepositoryInterface::class, 'credential_repository')
            ->setPublic(true);
    }
}
