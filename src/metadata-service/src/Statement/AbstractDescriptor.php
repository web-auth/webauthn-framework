<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;

abstract class AbstractDescriptor implements JsonSerializable
{
    private readonly ?int $maxRetries;

    private readonly ?int $blockSlowdown;

    public function __construct(?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        $maxRetries >= 0 || throw MetadataStatementLoadingException::create(
            'Invalid data. The value of "maxRetries" must be a positive integer'
        );
        $blockSlowdown >= 0 || throw MetadataStatementLoadingException::create(
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
