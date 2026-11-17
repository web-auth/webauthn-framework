<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\Config\Loader\LoaderInterface;

/**
 * Test application with endpoints that do not share the same user verification requirement: the firewall and the
 * request controller `step_up` require it, the request controller `lax` only prefers it. The options are kept by the
 * session storage of the bundle, which finds them by their challenge.
 */
final class OptionsScopeAppKernel extends AppKernel
{
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        parent::registerContainerConfiguration($loader);
        $loader->load(__DIR__ . '/../config/config-options-scope.yml');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-options-scope/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-options-scope/logs';
    }
}
