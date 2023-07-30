<?php

declare(strict_types=1);

namespace Webauthn;

use JsonSerializable;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;

abstract class PublicKeyCredentialOptions implements JsonSerializable
{
    /**
     * @var positive-int|null
     */
    public ?int $timeout = null;

    public AuthenticationExtensionsClientInputs $extensions;

    public function __construct(
        public readonly string $challenge
    ) {
        $this->extensions = AuthenticationExtensionsClientInputs::create();
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function setTimeout(?int $timeout): static
    {
        $this->timeout = $timeout;

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function addExtension(AuthenticationExtension $extension): static
    {
        $this->extensions[$extension->name] = $extension;

        return $this;
    }

    /**
     * @param AuthenticationExtension[] $extensions
     * @deprecated since 4.7.0. No replacement. Please use the property directly.
     */
    public function addExtensions(array $extensions): static
    {
        foreach ($extensions as $extension) {
            $this->extensions[$extension->name] = $extension;
        }

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function setExtensions(AuthenticationExtensionsClientInputs $extensions): static
    {
        $this->extensions = $extensions;

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getChallenge(): string
    {
        return $this->challenge;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getTimeout(): ?int
    {
        return $this->timeout;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getExtensions(): AuthenticationExtensionsClientInputs
    {
        return $this->extensions;
    }

    abstract public static function createFromString(string $data): static;

    /**
     * @param mixed[] $json
     */
    abstract public static function createFromArray(array $json): static;
}
