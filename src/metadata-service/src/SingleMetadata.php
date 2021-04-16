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

namespace Webauthn\MetadataService;

use JetBrains\PhpStorm\Pure;
use function Safe\base64_decode;
use function Safe\json_decode;

class SingleMetadata
{
    private ?MetadataStatement $statement = null;

    #[Pure]
    public function __construct(private string $data, private bool $isBase64Encoded)
    {
    }

    public function getMetadataStatement(): MetadataStatement
    {
        if (null === $this->statement) {
            $json = $this->data;
            if ($this->isBase64Encoded) {
                $json = base64_decode($this->data, true);
            }
            $statement = json_decode($json, true);
            $this->statement = MetadataStatement::createFromArray($statement);
        }

        return $this->statement;
    }
}
