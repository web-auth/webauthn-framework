<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\PublicKeyCredentialUserEntity;

final class User extends PublicKeyCredentialUserEntity implements UserInterface
{
    public function __construct(
        string $name,
        string $id,
        string $displayName,
        ?string $icon = null,
        private readonly array $roles = []
    ) {
        parent::__construct($name, $id, $displayName, $icon);
    }

    public function getRoles(): array
    {
        return array_unique($this->roles + ['ROLE_USER']);
    }

    public function getUsername(): string
    {
        return $this->getName();
    }

    public function eraseCredentials(): void
    {
    }

    public function getUserIdentifier(): string
    {
        return $this->name;
    }
}
