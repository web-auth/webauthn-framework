<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class UserRepository
{
    /**
     * @var CacheItemPoolInterface
     */
    private $cache;

    public function __construct(CacheItemPoolInterface $cache)
    {
        $this->cache = $cache;
        $this->saveUser(new User('uuid', 'admin', ['ROLE_ADMIN', 'ROLE_USER']));
    }

    public function saveUser(User $user): void
    {
        $item = $this->cache->getItem('users');
        $users = [];
        if ($item->isHit()) {
            $users = $item->get();
        }
        $users[$user->getUsername()] = $user;
        $item->set($users);
        $this->cache->save($item);
    }

    public function findByUsername(string $username): ?UserInterface
    {
        $item = $this->cache->getItem('users');
        $users = [];
        if ($item->isHit()) {
            $users = $item->get();
        }

        if (\array_key_exists($username, $users)) {
            return $users[$username];
        }

        return null;
    }
}
