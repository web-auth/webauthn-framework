<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

interface ExtensionOutput
{
    public function identifier(): string;
}
