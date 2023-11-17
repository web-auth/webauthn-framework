<?php

declare(strict_types=1);

namespace Webauthn\Bundle;

use Doctrine\Bundle\DoctrineBundle\DependencyInjection\Compiler\DoctrineOrmMappingsPass;
use LogicException;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Webauthn\Bundle\DependencyInjection\Compiler\AttestationStatementSupportCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CeremonyStepManagerFactoryCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CoseAlgorithmCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CounterCheckerSetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\EnforcedSafetyNetApiKeyVerificationCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\EventDispatcherSetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\ExtensionOutputCheckerCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\LoggerSetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\MetadataStatementSupportCompilerPass;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnFactory;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnServicesFactory;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;
use function realpath;

final class WebauthnBundle extends Bundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        return new WebauthnExtension('webauthn');
    }

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->addCompilerPass(
            new CeremonyStepManagerFactoryCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
        $container->addCompilerPass(
            new EventDispatcherSetterCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
        $container->addCompilerPass(
            new AttestationStatementSupportCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
        $container->addCompilerPass(
            new ExtensionOutputCheckerCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
        $container->addCompilerPass(new CoseAlgorithmCompilerPass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 0);
        $container->addCompilerPass(new DynamicRouteCompilerPass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 0);
        $container->addCompilerPass(
            new EnforcedSafetyNetApiKeyVerificationCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
        $container->addCompilerPass(new LoggerSetterCompilerPass(), PassConfig::TYPE_BEFORE_OPTIMIZATION, 0);
        $container->addCompilerPass(
            new CounterCheckerSetterCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );
        $container->addCompilerPass(
            new MetadataStatementSupportCompilerPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            0
        );

        $this->registerMappings($container);

        if ($container->hasExtension('security')) {
            $extension = $container->getExtension('security');
            $extension instanceof SecurityExtension || throw new LogicException(
                'The security extension is missing or invalid'
            );
            $extension->addAuthenticatorFactory(new WebauthnFactory(new WebauthnServicesFactory()));
        }
    }

    private function registerMappings(ContainerBuilder $container): void
    {
        $realPath = realpath(__DIR__ . '/Resources/config/doctrine-mapping');
        $mappings = [
            $realPath => 'Webauthn',
        ];
        if (class_exists(DoctrineOrmMappingsPass::class)) {
            $container->addCompilerPass(
                DoctrineOrmMappingsPass::createXmlMappingDriver($mappings, [], false, [], true),
                PassConfig::TYPE_BEFORE_OPTIMIZATION,
                0
            );
        }
    }
}
