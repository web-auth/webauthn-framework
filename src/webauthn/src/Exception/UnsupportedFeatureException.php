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

    public function __construct(string $feature, string $message, Throwable $previous = null)
    {
        parent::__construct($message, $previous);
        $this->feature = $feature;
    }

    public function getFeature(): string
    {
        return $this->feature;
    }

    public static function create(string $feature, string $message, ?Throwable $previous = null): callable
    {
        return static function () use ($feature, $message, $previous): self {
            return new self($feature, $message, $previous);
        };
    }
}
