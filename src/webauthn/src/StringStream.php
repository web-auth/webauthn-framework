<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use Assert\Assertion;
use CBOR\Stream;
use JetBrains\PhpStorm\Pure;
use function Safe\fclose;
use function Safe\fopen;
use function Safe\fread;
use function Safe\fwrite;
use function Safe\rewind;
use function Safe\sprintf;

final class StringStream implements Stream
{
    /**
     * @var resource
     */
    private $data;

    private int $length;

    private int $totalRead = 0;

    public function __construct(string $data)
    {
        $this->length = mb_strlen($data, '8bit');
        $resource = fopen('php://memory', 'rb+');
        fwrite($resource, $data);
        rewind($resource);
        $this->data = $resource;
    }

    public function read(int $length): string
    {
        if (0 === $length) {
            return '';
        }
        $read = fread($this->data, $length);
        $bytesRead = mb_strlen($read, '8bit');
        Assertion::length($read, $length, sprintf('Out of range. Expected: %d, read: %d.', $length, $bytesRead), null, '8bit');
        $this->totalRead += $bytesRead;

        return $read;
    }

    public function close(): void
    {
        fclose($this->data);
    }

    #[Pure]
    public function isEOF(): bool
    {
        return $this->totalRead === $this->length;
    }
}
