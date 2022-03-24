<?php

declare(strict_types=1);

namespace Cose\Key;

use function array_key_exists;
use Assert\Assertion;

class Key
{
    public const TYPE = 1;

    public const TYPE_OKP = 1;

    public const TYPE_EC2 = 2;

    public const TYPE_RSA = 3;

    public const TYPE_OCT = 4;

    public const KID = 2;

    public const ALG = 3;

    public const KEY_OPS = 4;

    public const BASE_IV = 5;

    /**
     * @var array<int, mixed>
     */
    private array $data;

    /**
     * @param array<int, mixed> $data
     */
    public function __construct(array $data)
    {
        Assertion::keyExists($data, self::TYPE, 'Invalid key: the type is not defined');
        $this->data = $data;
    }

    /**
     * @param array<int, mixed> $data
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    /**
     * @param array<int, mixed> $data
     */
    public static function createFromData(array $data): self
    {
        Assertion::keyExists($data, self::TYPE, 'Invalid key: the type is not defined');

        return match ($data[self::TYPE]) {
            '1' => new OkpKey($data),
            '2' => new Ec2Key($data),
            '3' => new RsaKey($data),
            '4' => new SymmetricKey($data),
            default => new self($data),
        };
    }

    public function type(): int|string
    {
        return $this->data[self::TYPE];
    }

    public function alg(): int
    {
        return (int) $this->get(self::ALG);
    }

    /**
     * @return array<int, mixed>
     */
    public function getData(): array
    {
        return $this->data;
    }

    public function has(int $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function get(int $key): mixed
    {
        Assertion::keyExists($this->data, $key, sprintf('The key has no data at index %d', $key));

        return $this->data[$key];
    }
}
