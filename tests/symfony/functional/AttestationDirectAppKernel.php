<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\Config\Loader\LoaderInterface;

/**
 * Test application whose default creation profile requests direct attestation, with the metadata service of the main
 * configuration and no client override policy of its own: the default policy of the bundle applies. The options are
 * kept by the session storage of the bundle, which finds them by their challenge.
 */
final class AttestationDirectAppKernel extends AppKernel
{
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        parent::registerContainerConfiguration($loader);
        $loader->load(__DIR__ . '/../config/config-attestation-direct.yml');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-attestation-direct/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-attestation-direct/logs';
    }
}
