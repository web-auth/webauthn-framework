<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use const JSON_THROW_ON_ERROR;

class SingleMetadata
{
    private ?MetadataStatement $statement = null;

    public function __construct(
        protected string $data,
        protected bool $isBase64Encoded
    ) {
    }

    public function getMetadataStatement(): MetadataStatement
    {
        if ($this->statement === null) {
            $json = $this->data;
            if ($this->isBase64Encoded) {
                $json = base64_decode($this->data, true);
                Assertion::string($json, 'Invalid data');
            }
            $statement = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
            $this->statement = MetadataStatement::createFromArray($statement);
        }

        return $this->statement;
    }
}
