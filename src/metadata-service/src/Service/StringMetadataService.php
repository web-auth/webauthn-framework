<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use function array_key_exists;
use Psr\EventDispatcher\EventDispatcherInterface;
use Webauthn\MetadataService\Event\MetadataStatementFound;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\MetadataService\Exception\MissingMetadataStatementException;
use Webauthn\MetadataService\Statement\MetadataStatement;

final class StringMetadataService implements MetadataService
{
    /**
     * @var MetadataStatement[]
     */
    private array $statements = [];

    private EventDispatcherInterface $dispatcher;

    public function __construct(string ...$statements)
    {
        foreach ($statements as $statement) {
            $this->addStatements(MetadataStatement::createFromString($statement));
        }
        $this->dispatcher = new NullEventDispatcher();
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): self
    {
        $this->dispatcher = $eventDispatcher;

        return $this;
    }

    public static function create(string ...$statements): self
    {
        return new self(...$statements);
    }

    public function addStatements(MetadataStatement ...$statements): self
    {
        foreach ($statements as $statement) {
            $aaguid = $statement->getAaguid();
            if ($aaguid === null) {
                continue;
            }
            $this->statements[$aaguid] = $statement;
        }

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
        array_key_exists($aaguid, $this->statements) || throw MissingMetadataStatementException::create($aaguid);
        $mds = $this->statements[$aaguid];
        $this->dispatcher->dispatch(MetadataStatementFound::create($mds));

        return $mds;
    }
}
