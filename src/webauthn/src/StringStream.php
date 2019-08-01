<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use CBOR\Stream;
use function Safe\sprintf;

final class StringStream implements Stream
{
    /**
     * @var string
     */
    private $data;

    public function __construct(string $data)
    {
        $this->data = $data;
    }

    public function read(int $length): string
    {
        if (0 === $length) {
            return '';
        }
        $data = mb_substr($this->data, 0, $length, '8bit');
        if (mb_strlen($data, '8bit') !== $length) {
            throw new \InvalidArgumentException(sprintf('Out of range. Expected: %d, read: %d.', $length, mb_strlen($data, '8bit')));
        }
        $this->data = mb_substr($this->data, $length, null, '8bit');

        return $data;
    }

    public function isEOF(): bool
    {
        return '' === $this->data;
    }
}
