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

final class UnsupportedFeatureException extends WebauthnException
{
    /**
     * @var string
     */
    private $feature;

    public function __construct(string $current, string $message, Throwable $previous = null)
    {
        parent::__construct($message, $previous);
        $this->feature = $current;
    }

    public function getFeature(): string
    {
        return $this->feature;
    }
}
