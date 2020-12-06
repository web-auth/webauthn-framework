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

final class InvalidCertificateException extends WebauthnException
{
    /**
     * @var string
     */
    private $certificate;

    public function __construct(string $certificate, string $message, ?Throwable $previous = null)
    {
        parent::__construct($message, $previous);
        $this->certificate = $certificate;
    }

    public function getAaguid(): string
    {
        return $this->certificate;
    }

    public static function create(string $certificate, string $message, ?Throwable $previous = null): callable
    {
        return static function () use ($certificate, $message, $previous): self {
            return new self($certificate, $message, $previous);
        };
    }
}
