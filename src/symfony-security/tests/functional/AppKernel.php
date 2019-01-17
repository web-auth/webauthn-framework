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

namespace Webauthn\SecurityBundle\Tests\Functional;

use SpomkyLabs\CborBundle\SpomkyLabsCborBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Kernel;
use Webauthn\Bundle\WebauthnBundle;
use Webauthn\SecurityBundle\WebauthnSecurityBundle;

final class AppKernel extends Kernel
{
    public function __construct(string $environment)
    {
        parent::__construct($environment, false);
    }

    public function registerBundles(): array
    {
        return [
            new FrameworkBundle(),
            new SpomkyLabsCborBundle(),
            new SecurityBundle(),
            new TwigBundle(),

            new WebauthnBundle(),
            new WebauthnSecurityBundle(),
        ];
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(__DIR__.'/../config/config.yml');
    }
}
