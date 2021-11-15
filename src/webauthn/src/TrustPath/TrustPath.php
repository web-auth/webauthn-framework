<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use JsonSerializable;

interface TrustPath extends JsonSerializable
{
    public static function createFromArray(array $data): self;
}
