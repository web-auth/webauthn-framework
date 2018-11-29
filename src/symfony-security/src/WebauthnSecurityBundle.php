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

namespace Webauthn\Security\Bundle;

use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Webauthn\Security\Bundle\DependencyInjection\WebauthnExtension;
use Webauthn\Security\Bundle\Security\Factory\WebauthnSecurityFactory;

class WebauthnSecurityBundle extends Bundle
{
    public function getContainerExtension()
    {
        return new WebauthnExtension();
    }

    public function build(ContainerBuilder $container)
    {
        /** @var SecurityExtension $extension */
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new WebauthnSecurityFactory());
    }
}
