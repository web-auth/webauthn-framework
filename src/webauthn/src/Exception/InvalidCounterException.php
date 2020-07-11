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

final class InvalidCounterException extends WebauthnException
{
    /**
     * @var int
     */
    private $current;

    /**
     * @var int
     */
    private $new;

    public function __construct(int $current, int $new, string $message, Throwable $previous = null)
    {
        parent::__construct($message, $previous);
        $this->current = $current;
        $this->new = $new;
    }

    public function getCurrent(): int
    {
        return $this->current;
    }

    public function getNew(): int
    {
        return $this->new;
    }
}
