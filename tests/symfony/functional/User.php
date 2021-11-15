<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\PublicKeyCredentialUserEntity;

final class User extends PublicKeyCredentialUserEntity implements UserInterface
{
    public function __construct(
        string $name,
        string $id,
        string $displayName,
        ?string $icon = null,
        private array $roles = []
    ) {
        parent::__construct($name, $id, $displayName, $icon);
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
