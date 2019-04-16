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

class Version
{
    /**
     * @var float
     */
    private $major;

    /**
     * @var float
     */
    private $minor;

    public function getMajor(): float
    {
        return $this->major;
    }

    public function getMinor(): float
    {
        return $this->minor;
    }

    public static function createFromArray(array $data): self
    {
        $object = new self();
        $object->major = $data['major'] ?? null;
        $object->minor = $data['minor'] ?? null;

        return $object;
    }
}
