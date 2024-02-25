<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\ValueFilter;

class PatternAccuracyDescriptor extends AbstractDescriptor
{
    use ValueFilter;

    public function __construct(
        public readonly int $minComplexity,
        ?int $maxRetries = null,
        ?int $blockSlowdown = null
    ) {
        $minComplexity >= 0 || throw MetadataStatementLoadingException::create(
            'Invalid data. The value of "minComplexity" must be a positive integer'
        );
        parent::__construct($maxRetries, $blockSlowdown);
    }

    public static function create(int $minComplexity, ?int $maxRetries = null, ?int $blockSlowdown = null): self
    {
        return new self($minComplexity, $maxRetries, $blockSlowdown);
    }

    /**
     * @return array<string, int|null>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'minComplexity' => $this->minComplexity,
            'maxRetries' => $this->maxRetries,
            'blockSlowdown' => $this->blockSlowdown,
        ];

        return self::filterNullValues($data);
    }
}
