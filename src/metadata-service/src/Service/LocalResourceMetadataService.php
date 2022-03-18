<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use function sprintf;
use Webauthn\MetadataService\Statement\MetadataStatement;

final class LocalResourceMetadataService implements MetadataService
{
    private ?MetadataStatement $statement = null;

    public function __construct(
        private string $filename,
        private bool $isBase64Encoded = false,
    ) {
    }

    public static function create(string $filename, bool $isBase64Encoded = false): self
    {
        return new self($filename, $isBase64Encoded);
    }

    public function list(): iterable
    {
        $this->loadData();

        yield from [$this->statement->getAaguid()];
    }

    public function has(string $aaguid): bool
    {
        $this->loadData();

        return $aaguid === $this->statement->getAaguid();
    }

    public function get(string $aaguid): MetadataStatement
    {
        $this->loadData();

        if ($aaguid === $this->statement->getAaguid()) {
            return $this->statement;
        }

        throw new InvalidArgumentException(sprintf('The Metadata Statement with AAGUID "%s" is missing', $aaguid));
    }

    private function loadData(): void
    {
        if ($this->statement !== null) {
            return;
        }

        $content = file_get_contents($this->filename);
        if ($this->isBase64Encoded) {
            $content = Base64::decode($content);
        }
        $this->statement = MetadataStatement::createFromString($content);
    }
}
