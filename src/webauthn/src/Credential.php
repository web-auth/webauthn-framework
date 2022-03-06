<?php

declare(strict_types=1);

namespace Webauthn;

/**
 * @see https://w3c.github.io/webappsec-credential-management/#credential
 */
abstract class Credential
{
    public function __construct(
        protected string $id,
        protected string $type
    ) {
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getType(): string
    {
        return $this->type;
    }
}
