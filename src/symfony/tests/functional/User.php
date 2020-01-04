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

use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\PublicKeyCredentialUserEntity;

final class User extends PublicKeyCredentialUserEntity implements UserInterface
{
    /**
     * @var array
     */
    private $roles;

    public function __construct(string $name, string $id, string $displayName, ?string $icon = null, array $roles = [])
    {
        parent::__construct($name, $id, $displayName, $icon);
        $this->roles = $roles;
    }

    public function getRoles(): array
    {
        return array_unique($this->roles + ['ROLE_USER']);
    }

    public function getPassword(): void
    {
    }

    public function getSalt(): void
    {
    }

    public function getUsername(): string
    {
        return $this->getName();
    }

    public function eraseCredentials(): void
    {
    }
}
