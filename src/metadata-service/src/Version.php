<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use function array_key_exists;
use Assert\Assertion;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use LogicException;
use function Safe\sprintf;

class Version implements JsonSerializable
{
    private ?int $major;

    private ?int $minor;

    public function __construct(?int $major, ?int $minor)
    {
        if (null === $major && null === $minor) {
            throw new LogicException('Invalid data. Must contain at least one item');
        }
        Assertion::greaterOrEqualThan($major, 0, Utils::logicException('Invalid argument "major"'));
        Assertion::greaterOrEqualThan($minor, 0, Utils::logicException('Invalid argument "minor"'));

        $this->major = $major;
        $this->minor = $minor;
    }

    #[Pure]
    public function getMajor(): ?int
    {
        return $this->major;
    }

    #[Pure]
    public function getMinor(): ?int
    {
        return $this->minor;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        foreach (['major', 'minor'] as $key) {
            if (array_key_exists($key, $data)) {
                Assertion::integer($data[$key], sprintf('Invalid value for key "%s"', $key));
            }
        }

        return new self(
            $data['major'] ?? null,
            $data['minor'] ?? null
        );
    }

    #[Pure]
    public function jsonSerialize(): array
    {
        $data = [
            'major' => $this->major,
            'minor' => $this->minor,
        ];

        return Utils::filterNullValues($data);
    }
}
