<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;

abstract class AbstractDescriptor implements JsonSerializable
{
    private ?int $maxRetries;

    private ?int $blockSlowdown;

    public function __construct(?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        Assertion::greaterOrEqualThan($maxRetries, 0, Utils::logicException('Invalid data. The value of "maxRetries" must be a positive integer'));
        Assertion::greaterOrEqualThan($blockSlowdown, 0, Utils::logicException('Invalid data. The value of "blockSlowdown" must be a positive integer'));

        $this->maxRetries = $maxRetries;
        $this->blockSlowdown = $blockSlowdown;
    }

    #[Pure]
    public function getMaxRetries(): ?int
    {
        return $this->maxRetries;
    }

    #[Pure]
    public function getBlockSlowdown(): ?int
    {
        return $this->blockSlowdown;
    }
}
