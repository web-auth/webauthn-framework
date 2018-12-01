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

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\Bundle\Model\CanHaveRegisteredSecurityDevices;

final class User implements UserInterface, CanHaveRegisteredSecurityDevices
{
    private $username;
    private $roles;
    private $registered_devices;

    public function __construct(string $username, array $roles, array $registered_devices)
    {
        $this->username = $username;
        $this->roles = $roles;
        $this->registered_devices = $registered_devices;
    }

    public function getSecurityDeviceCredentialIds(): iterable
    {
        yield from $this->registered_devices;
    }

    public function getRoles()
    {
        return $this->roles + ['ROLE_USER'];
    }

    public function getPassword()
    {
        return;
    }

    public function getSalt()
    {
        return;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function eraseCredentials()
    {
    }
}
