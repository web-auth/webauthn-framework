<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * @final
 */
class TwoFactorProviderNotFoundException extends AuthenticationException
{
    public const MESSAGE_KEY = 'Two-factor provider not found.';

    /**
     * @psalm-suppress PropertyNotSetInConstructor
     */
    private ?string $provider;

    /**
     * @return mixed[]
     */
    public function __serialize(): array
    {
        return [$this->provider, parent::__serialize()];
    }

    /**
     * @param mixed[] $data
     */
    public function __unserialize(array $data): void
    {
        [$this->provider, $parentData] = $data;
        parent::__unserialize($parentData);
    }

    public function getMessageKey(): string
    {
        return self::MESSAGE_KEY;
    }

    public function getProvider(): ?string
    {
        return $this->provider;
    }

    public function setProvider(string $provider): void
    {
        $this->provider = $provider;
    }

    /**
     * @return array<string,string|null>
     */
    public function getMessageData(): array
    {
        return [
            '{{ provider }}' => $this->provider,
        ];
    }
}
