<?php

declare(strict_types=1);

namespace Cose\Key;

use function array_key_exists;
use Assert\Assertion;
use JetBrains\PhpStorm\Pure;
use function Safe\sprintf;

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

    private array $data;

    public function __construct(array $data)
    {
        Assertion::keyExists($data, self::TYPE, 'Invalid key: the type is not defined');
        $this->data = $data;
    }

    public static function create(array $data): self
    {
        return new self($data);
    }

    public static function createFromData(array $data): self
    {
        Assertion::keyExists($data, self::TYPE, 'Invalid key: the type is not defined');

        return match ((int) $data[self::TYPE]) {
            4 => SymmetricKey::create($data),
            3 => RsaKey::create($data),
            2 => Ec2Key::create($data),
            1 => OkpKey::create($data),
            default => new self($data),
        };
    }

    #[Pure]
    public function type(): int | string
    {
        return $this->data[self::TYPE];
    }

    public function alg(): int
    {
        return (int) $this->get(self::ALG);
    }

    #[Pure]
    public function getData(): array
    {
        return $this->data;
    }

    #[Pure]
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
