<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use Assert\Assertion;
use Webauthn\MetadataService\MetadataStatement;
use function Safe\sprintf;

final class InMemoryMetadataService implements MetadataService
{
    /**
     * @var MetadataStatement[]
     */
    private array $statements = [];

    public function __construct(MetadataStatement ...$statements)
    {
        foreach($statements as $statement) {
            $this->addStatement($statement);
        }
    }

    public function addStatement(MetadataStatement $statement): self
    {
        $aaguid = $statement->getAaguid();
        Assertion::notNull($aaguid, 'The attestation statement has not AAGUID');
        $this->statements[$aaguid] = $statement;

        return $this;
    }

    public function list(): iterable
    {
        yield from array_keys($this->statements);
    }

    public function has(string $aaguid): bool
    {
        return array_key_exists($aaguid, $this->statements);
    }

    public function get(string $aaguid): MetadataStatement
    {
        Assertion::keyExists($this->statements, $aaguid, sprintf('The Metadata Statement with AAGUID "%s" is missing', $aaguid));

        return $this->statements[$aaguid];
    }
}
