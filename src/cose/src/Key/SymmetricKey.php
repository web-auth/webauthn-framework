<?php

declare(strict_types=1);

namespace Cose\Key;

use Assert\Assertion;

class SymmetricKey extends Key
{
    public const DATA_K = -1;

    /**
     * @param array<int, mixed> $data
     */
    public function __construct(array $data)
    {
        parent::__construct($data);
        Assertion::eq(
            $data[self::TYPE],
            self::TYPE_OCT,
            'Invalid symmetric key. The key type does not correspond to a symmetric key'
        );
        Assertion::keyExists($data, self::DATA_K, 'Invalid symmetric key. The parameter "k" is missing');
    }

    /**
     * @param array<int, mixed> $data
     */
    public static function create(array $data): self
    {
        return new self($data);
    }

    public function k(): string
    {
        return $this->get(self::DATA_K);
    }
}
