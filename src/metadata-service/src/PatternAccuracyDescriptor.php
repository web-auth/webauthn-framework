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

class PatternAccuracyDescriptor
{
    /**
     * @var float
     */
    private $minComplexity;

    /**
     * @var float|null
     */
    private $maxRetries;

    /**
     * @var float|null
     */
    private $blockSlowdown;

    public function getMinComplexity(): float
    {
        return $this->minComplexity;
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
        $object->minComplexity = $data['minComplexity'] ?? null;
        $object->maxRetries = $data['maxRetries'] ?? null;
        $object->blockSlowdown = $data['blockSlowdown'] ?? null;

        return $object;
    }
}
