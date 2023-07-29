<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;
use function array_key_exists;
use function is_int;

/**
 * @final
 */
class PatternAccuracyDescriptor extends AbstractDescriptor
{
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
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getMinComplexity(): int
    {
        return $this->minComplexity;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        array_key_exists('minComplexity', $data) || throw MetadataStatementLoadingException::create(
            'The key "minComplexity" is missing'
        );
        foreach (['minComplexity', 'maxRetries', 'blockSlowdown'] as $key) {
            if (array_key_exists($key, $data)) {
                is_int($data[$key]) || throw MetadataStatementLoadingException::create(
                    sprintf('Invalid data. The value of "%s" must be a positive integer', $key)
                );
            }
        }

        return self::create($data['minComplexity'], $data['maxRetries'] ?? null, $data['blockSlowdown'] ?? null);
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

        return Utils::filterNullValues($data);
    }
}
