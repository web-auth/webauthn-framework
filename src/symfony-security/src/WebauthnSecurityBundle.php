<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\SecurityBundle;

use Assert\Assertion;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Webauthn\SecurityBundle\DependencyInjection\WebauthnSecurityExtension;
use Webauthn\SecurityBundle\Security\Factory\WebauthnSecurityFactory;

final class WebauthnSecurityBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function getContainerExtension()
    {
        return new WebauthnSecurityExtension('webauthn_security');
    }

    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container): void
    {
        if ($container->hasExtension('security')) {
            $extension = $container->getExtension('security');
            Assertion::isInstanceOf($extension, SecurityExtension::class, 'The security extension is missing or invalid');
            $extension->addSecurityListenerFactory(new WebauthnSecurityFactory());
        }
    }
}
