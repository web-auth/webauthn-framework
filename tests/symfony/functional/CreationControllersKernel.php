<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\Config\Loader\LoaderInterface;

/**
 * The test application with the options storage of the bundle and two more creation controllers: `add_passkey`, behind
 * the `^/devices/add` access control, adds a credential to the account of the signed-in user, and `signup`, open to
 * visitors, guesses the user from the request body.
 */
final class CreationControllersKernel extends AppKernel
{
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        parent::registerContainerConfiguration($loader);
        $loader->load(__DIR__ . '/../config/config-creation-controllers.yml');
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-creation-controllers/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/webauthn-creation-controllers/logs';
    }
}
