<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use JsonSerializable;

interface ExtensionInput extends JsonSerializable
{
    public function identifier(): string;
}
