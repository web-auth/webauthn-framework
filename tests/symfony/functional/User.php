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

use JetBrains\PhpStorm\Pure;
use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\PublicKeyCredentialUserEntity;

final class User extends PublicKeyCredentialUserEntity implements UserInterface
{
    public function __construct(string $name, string $id, string $displayName, ?string $icon = null, private array $roles = [])
    {
        parent::__construct($name, $id, $displayName, $icon);
    }

    public static function create(string $name, string $id, string $displayName, ?string $icon = null, array $roles = []): self
    {
        return new self($name, $id, $displayName, $icon, $roles);
    }

    #[Pure]
    public function getRoles(): array
    {
        return array_unique($this->roles + ['ROLE_USER']);
    }

    #[Pure]
    public function getPassword(): void
    {
    }

    #[Pure]
    public function getSalt(): void
    {
    }

    #[Pure]
    public function getUsername(): string
    {
        return $this->getName();
    }

    #[Pure]
    public function eraseCredentials(): void
    {
    }
}
