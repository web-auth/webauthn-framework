<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;
use function array_key_exists;

/**
 * @final
 */
class CodeAccuracyDescriptor extends AbstractDescriptor
{
    public function __construct(
        public readonly int $base,
        public readonly int $minLength,
        ?int $maxRetries = null,
        ?int $blockSlowdown = null
    ) {
        $base >= 0 || throw MetadataStatementLoadingException::create(
            'Invalid data. The value of "base" must be a positive integer'
        );
        $minLength >= 0 || throw MetadataStatementLoadingException::create(
            'Invalid data. The value of "minLength" must be a positive integer'
        );
        parent::__construct($maxRetries, $blockSlowdown);
    }

    public static function create(int $base, int $minLength, ?int $maxRetries = null, ?int $blockSlowdown = null): self
    {
        return new self($base, $minLength, $maxRetries, $blockSlowdown);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getBase(): int
    {
        return $this->base;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getMinLength(): int
    {
        return $this->minLength;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        array_key_exists('base', $data) || throw MetadataStatementLoadingException::create(
            'The parameter "base" is missing'
        );
        array_key_exists('minLength', $data) || throw MetadataStatementLoadingException::create(
            'The parameter "minLength" is missing'
        );

        return self::create(
            $data['base'],
            $data['minLength'],
            $data['maxRetries'] ?? null,
            $data['blockSlowdown'] ?? null
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'base' => $this->base,
            'minLength' => $this->minLength,
            'maxRetries' => $this->maxRetries,
            'blockSlowdown' => $this->blockSlowdown,
        ];

        return Utils::filterNullValues($data);
    }
}
