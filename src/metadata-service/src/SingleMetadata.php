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

use function Safe\base64_decode;
use function Safe\json_decode;

class SingleMetadata
{
    /**
     * @var MetadataStatement
     */
    private $statement;
    /**
     * @var string
     */
    private $data;
    /**
     * @var bool
     */
    private $isBare64Encoded;

    public function __construct(string $data, bool $isBare64Encoded)
    {
        $this->data = $data;
        $this->isBare64Encoded = $isBare64Encoded;
    }

    public function getMetadataStatement(): MetadataStatement
    {
        if (null === $this->statement) {
            $json = $this->isBare64Encoded ? base64_decode($this->data, true) : $this->data;
            $statement = json_decode($json, true);
            $this->statement = MetadataStatement::createFromArray($statement);
        }

        return $this->statement;
    }
}
