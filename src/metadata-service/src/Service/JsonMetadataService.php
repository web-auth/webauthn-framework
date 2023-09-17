<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\MetadataService\Denormalizer\MetadataStatementSerializerFactory;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\MetadataStatementFound;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\MetadataService\Exception\MissingMetadataStatementException;
use Webauthn\MetadataService\Statement\MetadataStatement;
use function array_key_exists;

final class JsonMetadataService implements MetadataService, CanDispatchEvents
{
    /**
     * @var MetadataStatement[]
     */
    private array $statements = [];

    private EventDispatcherInterface $dispatcher;

    private readonly ?SerializerInterface $serializer;

    /**
     * @param string[] $statements
     */
    public function __construct(
        array $statements,
        ?SerializerInterface $serializer = null,
    ) {
        $this->dispatcher = new NullEventDispatcher();
        $this->serializer = $serializer ?? MetadataStatementSerializerFactory::create();
        foreach ($statements as $statement) {
            $this->addStatement($statement);
        }
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->dispatcher = $eventDispatcher;
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

    private function addStatement(string $statement): void
    {
        if ($this->serializer === null) {
            $mds = MetadataStatement::createFromString($statement);
        } else {
            $mds = $this->serializer->deserialize($statement, MetadataStatement::class, 'json');
        }
        if ($mds->aaguid === null) {
            return;
        }
        $this->statements[$mds->aaguid] = $mds;
    }
}
