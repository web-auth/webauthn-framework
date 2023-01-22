<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function array_key_exists;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;

/**
 * @final
 */
class CodeAccuracyDescriptor extends AbstractDescriptor
{
    private readonly int $base;

    private readonly int $minLength;

    public function __construct(int $base, int $minLength, ?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        $base >= 0 || throw MetadataStatementLoadingException::create(
            'Invalid data. The value of "base" must be a positive integer'
        );
        $minLength >= 0 || throw MetadataStatementLoadingException::create(
            'Invalid data. The value of "minLength" must be a positive integer'
        );
        $this->base = $base;
        $this->minLength = $minLength;
        parent::__construct($maxRetries, $blockSlowdown);
    }

    public function getBase(): int
    {
        return $this->base;
    }

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

        return new self(
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
            'maxRetries' => $this->getMaxRetries(),
            'blockSlowdown' => $this->getBlockSlowdown(),
        ];

        return Utils::filterNullValues($data);
    }
}
