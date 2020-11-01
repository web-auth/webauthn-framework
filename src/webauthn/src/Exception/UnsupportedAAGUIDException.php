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

final class UnsupportedAAGUIDException extends WebauthnException
{
    /**
     * @var string
     */
    private $aaguid;

    public function __construct(string $aaguid, string $message, Throwable $previous = null)
    {
        parent::__construct($message, $previous);
        $this->aaguid = $aaguid;
    }

    public function getAAGUID(): string
    {
        return $this->aaguid;
    }

    public static function create(string $aaguid, string $message, ?Throwable $previous = null): callable
    {
        return static function () use ($aaguid, $message, $previous) {
            return new self($aaguid, $message, $previous);
        };
    }
}
