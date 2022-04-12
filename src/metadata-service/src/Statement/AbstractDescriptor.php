<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Assert\Assertion;
use JsonSerializable;

abstract class AbstractDescriptor implements JsonSerializable
{
    private readonly ?int $maxRetries;

    private readonly ?int $blockSlowdown;

    public function __construct(?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        Assertion::greaterOrEqualThan(
            $maxRetries,
            0,
            'Invalid data. The value of "maxRetries" must be a positive integer'
        );
        Assertion::greaterOrEqualThan(
            $blockSlowdown,
            0,
            'Invalid data. The value of "blockSlowdown" must be a positive integer'
        );

        $this->maxRetries = $maxRetries;
        $this->blockSlowdown = $blockSlowdown;
    }

    public function getMaxRetries(): ?int
    {
        return $this->maxRetries;
    }

    public function getBlockSlowdown(): ?int
    {
        return $this->blockSlowdown;
    }
}
