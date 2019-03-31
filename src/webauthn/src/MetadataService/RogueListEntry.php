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

class RogueListEntry implements \JsonSerializable
{
    /**
     * @var string
     */
    private $sk;
    /**
     * @var string
     */
    private $date;

    public function getSk(): string
    {
        return $this->sk;
    }

    public function setSk(string $sk): void
    {
        $this->sk = $sk;
    }

    public function getDate(): string
    {
        return $this->date;
    }

    public function setDate(string $date): void
    {
        $this->date = $date;
    }

    public function jsonSerialize(): array
    {
        return [
        ];
    }
}
