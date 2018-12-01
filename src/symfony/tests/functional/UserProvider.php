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
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class UserProvider implements UserProviderInterface
{
    public function loadUserByUsername($username)
    {
        dump($username);
    }

    public function refreshUser(UserInterface $user)
    {
        dump($user);
    }

    public function supportsClass($class)
    {
        return $class instanceof User;
    }
}
