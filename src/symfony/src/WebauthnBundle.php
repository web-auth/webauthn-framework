<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle;

use Assert\Assertion;
use Doctrine\Bundle\DoctrineBundle\DependencyInjection\Compiler\DoctrineOrmMappingsPass;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Webauthn\Bundle\DependencyInjection\Compiler\AttestationStatementSupportCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\CoseAlgorithmCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\DynamicRouteCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\ExtensionOutputCheckerCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\MetadataServiceCompilerPass;
use Webauthn\Bundle\DependencyInjection\Compiler\SingleMetadataCompilerPass;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;
use Webauthn\Bundle\Security\Factory\WebauthnSecurityFactory;

final class WebauthnBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function getContainerExtension()
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
        $container->addCompilerPass(new MetadataServiceCompilerPass());
        $container->addCompilerPass(new SingleMetadataCompilerPass());

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
        Assertion::string($realPath, sprintf('Unable to get the real path of "%s"', __DIR__.'/Resources/config/doctrine-mapping'));
        $mappings = [$realPath => 'Webauthn'];
        if (class_exists('Doctrine\Bundle\DoctrineBundle\DependencyInjection\Compiler\DoctrineOrmMappingsPass')) {
            $container->addCompilerPass(DoctrineOrmMappingsPass::createXmlMappingDriver($mappings, []));
        }
    }
}
