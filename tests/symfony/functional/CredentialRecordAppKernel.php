<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\Config\Loader\LoaderInterface;

/**
 * Application configured with a repository that only implements the 5.3 interfaces.
 */
final class CredentialRecordAppKernel extends AppKernel
{
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        parent::registerContainerConfiguration($loader);
        $loader->load(__DIR__ . '/../config/config-credential-record.yml');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-credential-record/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-credential-record/logs';
    }
}
