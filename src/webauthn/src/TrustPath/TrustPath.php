<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use JsonSerializable;

interface TrustPath extends JsonSerializable
{
    /**
     * @param mixed[] $data
     */
    public static function createFromArray(array $data): self;
}
