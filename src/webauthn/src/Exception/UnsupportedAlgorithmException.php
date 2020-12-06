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

namespace Webauthn\Exception;

use Throwable;

final class UnsupportedAlgorithmException extends WebauthnException
{
    /**
     * @var int
     */
    private $algorithm;

    public function __construct(int $algorithm, string $message, Throwable $previous = null)
    {
        parent::__construct($message, $previous);
        $this->algorithm = $algorithm;
    }

    public function getAlgorithm(): int
    {
        return $this->algorithm;
    }

    public static function create(int $algorithm, string $message, ?Throwable $previous = null): callable
    {
        return static function () use ($algorithm, $message, $previous): self {
            return new self($algorithm, $message, $previous);
        };
    }
}
