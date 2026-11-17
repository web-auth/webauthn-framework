<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\Config\Loader\LoaderInterface;

/**
 * Application with a "staff" user provider declared before "default", the provider of the "main" firewall. Its
 * configuration is loaded first so that the chain of every user provider asks "staff" first.
 */
final class MultipleUserProvidersAppKernel extends AppKernel
{
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(__DIR__ . '/../config/config-multiple-user-providers.yml');
        parent::registerContainerConfiguration($loader);
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-multiple-user-providers/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-multiple-user-providers/logs';
    }
}
