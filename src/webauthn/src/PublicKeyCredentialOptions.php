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

namespace Webauthn;

use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;

abstract class PublicKeyCredentialOptions implements JsonSerializable
{
    protected ?int $timeout = null;

    protected AuthenticationExtensionsClientInputs $extensions;

    #[Pure]
    public function __construct(protected string $challenge)
    {
        $this->extensions = AuthenticationExtensionsClientInputs::create();
    }

    public function setTimeout(?int $timeout): static
    {
        $this->timeout = $timeout;

        return $this;
    }

    public function addExtension(AuthenticationExtension $extension): static
    {
        $this->extensions->add($extension);

        return $this;
    }

    /**
     * @param AuthenticationExtension[] $extensions
     */
    public function addExtensions(array $extensions): static
    {
        foreach ($extensions as $extension) {
            $this->addExtension($extension);
        }

        return $this;
    }

    public function setExtensions(AuthenticationExtensionsClientInputs $extensions): static
    {
        $this->extensions = $extensions;

        return $this;
    }

    #[Pure]
    public function getChallenge(): string
    {
        return $this->challenge;
    }

    #[Pure]
    public function getTimeout(): ?int
    {
        return $this->timeout;
    }

    #[Pure]
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
