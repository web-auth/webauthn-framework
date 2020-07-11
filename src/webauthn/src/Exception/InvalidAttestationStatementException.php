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

final class InvalidAttestationStatementException extends WebauthnException
{
    /**
     * @var string
     */
    private $format;

    public function __construct(string $format, string $message, Throwable $previous = null)
    {
        parent::__construct($message, $previous);
        $this->format = $format;
    }

    public static function throw(string $format, string $message, Throwable $previous = null): callable
    {
        return static function () use ($format, $message, $previous): InvalidAttestationStatementException {
            return new InvalidAttestationStatementException($format, $message, $previous);
        };
    }

    public function getFormat(): string
    {
        return $this->format;
    }
}
