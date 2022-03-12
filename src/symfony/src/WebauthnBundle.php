<?php

declare(strict_types=1);

namespace Webauthn\Bundle;

use Assert\Assertion;
use Doctrine\Bundle\DoctrineBundle\DependencyInjection\Compiler\DoctrineOrmMappingsPass;
use function Safe\realpath;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Webauthn\Bundle\DependencyInjection\Compiler\AttestationStatementSupportCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CertificateChainCheckerSetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CoseAlgorithmCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CounterCheckerSetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\EnforcedSafetyNetApiKeyVerificationCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\ExtensionOutputCheckerCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\LoggerSetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\MetadataStatementRepositorySetterCompilerPass;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;
use Webauthn\Bundle\Security\Factory\WebauthnSecurityFactory;

final class WebauthnBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    
    public function getContainerExtension(): ExtensionInterface
    {
        return new WebauthnExtension('webauthn');
    }

    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);
        $container->addCompilerPass(new AttestationStatementSupportCompilerPass());
        $container->addCompilerPass(new ExtensionOutputCheckerCompilerPass());
        $container->addCompilerPass(new CoseAlgorithmCompilerPass());
        $container->addCompilerPass(new DynamicRouteCompilerPass());
        $container->addCompilerPass(new EnforcedSafetyNetApiKeyVerificationCompilerPass());
        $container->addCompilerPass(new LoggerSetterCompilerPass());
        $container->addCompilerPass(new CounterCheckerSetterCompilerPass());
        $container->addCompilerPass(new CertificateChainCheckerSetterCompilerPass());
        $container->addCompilerPass(new MetadataStatementRepositorySetterCompilerPass());

        $this->registerMappings($container);

        if ($container->hasExtension('security')) {
            $extension = $container->getExtension('security');
            Assertion::isInstanceOf($extension, SecurityExtension::class, 'The security extension is missing or invalid');
            $extension->addSecurityListenerFactory(new WebauthnSecurityFactory());
        }
    }

    private function registerMappings(ContainerBuilder $container): void
    {
        $realPath = realpath(__DIR__.'/Resources/config/doctrine-mapping');
        $mappings = [$realPath => 'Webauthn'];
        if (class_exists('Doctrine\Bundle\DoctrineBundle\DependencyInjection\Compiler\DoctrineOrmMappingsPass')) {
            $container->addCompilerPass(DoctrineOrmMappingsPass::createXmlMappingDriver($mappings, []));
        }
    }
}
