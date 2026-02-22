<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\Config\Loader\LoaderInterface;

final class LockDownAppKernel extends AppKernel
{
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        parent::registerContainerConfiguration($loader);
        $loader->load(__DIR__ . '/../config/config-lockdown.yml');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-lockdown/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-lockdown/logs';
    }
}
