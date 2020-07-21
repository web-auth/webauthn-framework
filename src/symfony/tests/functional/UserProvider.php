<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional;

use function Safe\sprintf;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class UserProvider implements UserProviderInterface
{
    /**
     * @var PublicKeyCredentialUserEntityRepository
     */
    private $userRepository;

    public function __construct(PublicKeyCredentialUserEntityRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username): UserInterface
    {
        $user = $this->userRepository->findOneByUsername($username);
        if (!$user instanceof User) {
            throw new UsernameNotFoundException(sprintf('The user with username "%s" cannot be found', $username));
        }

        return $user;
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        return $this->loadUserByUsername($user->getUsername());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class): bool
    {
        return User::class === $class || is_subclass_of($class, User::class);
    }
}
