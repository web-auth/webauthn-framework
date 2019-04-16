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

namespace Webauthn\MetadataService;

class CodeAccuracyDescriptor
{
    /**
     * @var float
     */
    private $base;

    /**
     * @var float
     */
    private $minLength;

    /**
     * @var float|null
     */
    private $maxRetries;

    /**
     * @var float|null
     */
    private $blockSlowdown;

    public function getBase(): float
    {
        return $this->base;
    }

    public function getMinLength(): float
    {
        return $this->minLength;
    }

    public function getMaxRetries(): ?float
    {
        return $this->maxRetries;
    }

    public function getBlockSlowdown(): ?float
    {
        return $this->blockSlowdown;
    }

    public static function createFromArray(array $data): self
    {
        $object = new self();
        $object->base = $data['base'] ?? null;
        $object->minLength = $data['minLength'] ?? null;
        $object->maxRetries = $data['maxRetries'] ?? null;
        $object->blockSlowdown = $data['blockSlowdown'] ?? null;

        return $object;
    }
}
