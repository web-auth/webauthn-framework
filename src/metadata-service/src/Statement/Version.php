<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;
use function array_key_exists;
use function is_int;

/**
 * @final
 */
class Version implements JsonSerializable
{
    public function __construct(
        public readonly ?int $major,
        public readonly ?int $minor
    ) {
        if ($major === null && $minor === null) {
            throw MetadataStatementLoadingException::create('Invalid data. Must contain at least one item');
        }
        $major >= 0 || throw MetadataStatementLoadingException::create('Invalid argument "major"');
        $minor >= 0 || throw MetadataStatementLoadingException::create('Invalid argument "minor"');
    }

    public static function create(?int $major, ?int $minor): self
    {
        return new self($major, $minor);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getMajor(): ?int
    {
        return $this->major;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getMinor(): ?int
    {
        return $this->minor;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        foreach (['major', 'minor'] as $key) {
            if (array_key_exists($key, $data)) {
                is_int($data[$key]) || throw MetadataStatementLoadingException::create(
                    sprintf('Invalid value for key "%s"', $key)
                );
            }
        }

        return self::create($data['major'] ?? null, $data['minor'] ?? null);
    }

    /**
     * @return array<string, int|null>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'major' => $this->major,
            'minor' => $this->minor,
        ];

        return Utils::filterNullValues($data);
    }
}
