<?php

declare(strict_types=1);

namespace Webauthn;

use JsonSerializable;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;

abstract class PublicKeyCredentialOptions implements JsonSerializable
{
    protected ?int $timeout = null;

    protected AuthenticationExtensionsClientInputs $extensions;

    public function __construct(
        protected string $challenge
    ) {
        $this->extensions = new AuthenticationExtensionsClientInputs();
    }

    public function setTimeout(?int $timeout): self
    {
        $this->timeout = $timeout;

        return $this;
    }

    public function addExtension(AuthenticationExtension $extension): self
    {
        $this->extensions->add($extension);

        return $this;
    }

    /**
     * @param AuthenticationExtension[] $extensions
     */
    public function addExtensions(array $extensions): self
    {
        foreach ($extensions as $extension) {
            $this->addExtension($extension);
        }

        return $this;
    }

    public function setExtensions(AuthenticationExtensionsClientInputs $extensions): self
    {
        $this->extensions = $extensions;

        return $this;
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    public function getTimeout(): ?int
    {
        return $this->timeout;
    }

    public function getExtensions(): AuthenticationExtensionsClientInputs
    {
        return $this->extensions;
    }

    abstract public static function createFromString(string $data): self;

    /**
     * @param mixed[] $json
     */
    abstract public static function createFromArray(array $json): self;
}
