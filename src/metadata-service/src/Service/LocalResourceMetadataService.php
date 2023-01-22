<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use function file_get_contents;
use ParagonIE\ConstantTime\Base64;
use Psr\EventDispatcher\EventDispatcherInterface;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\MetadataStatementFound;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Exception\MissingMetadataStatementException;
use Webauthn\MetadataService\Statement\MetadataStatement;

final class LocalResourceMetadataService implements MetadataService, CanDispatchEvents
{
    private ?MetadataStatement $statement = null;

    private EventDispatcherInterface $dispatcher;

    public function __construct(
        private readonly string $filename,
        private readonly bool $isBase64Encoded = false,
    ) {
        $this->dispatcher = new NullEventDispatcher();
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->dispatcher = $eventDispatcher;
    }

    public static function create(string $filename, bool $isBase64Encoded = false): self
    {
        return new self($filename, $isBase64Encoded);
    }

    public function list(): iterable
    {
        $this->loadData();
        $this->statement !== null || throw MetadataStatementLoadingException::create(
            'Unable to load the metadata statement'
        );
        $aaguid = $this->statement->getAaguid();
        if ($aaguid === null) {
            yield from [];
        } else {
            yield from [$aaguid];
        }
    }

    public function has(string $aaguid): bool
    {
        $this->loadData();
        $this->statement !== null || throw MetadataStatementLoadingException::create(
            'Unable to load the metadata statement'
        );

        return $aaguid === $this->statement->getAaguid();
    }

    public function get(string $aaguid): MetadataStatement
    {
        $this->loadData();
        $this->statement !== null || throw MetadataStatementLoadingException::create(
            'Unable to load the metadata statement'
        );

        if ($aaguid === $this->statement->getAaguid()) {
            $this->dispatcher->dispatch(MetadataStatementFound::create($this->statement));

            return $this->statement;
        }

        throw MissingMetadataStatementException::create($aaguid);
    }

    private function loadData(): void
    {
        if ($this->statement !== null) {
            return;
        }

        $content = file_get_contents($this->filename);
        if ($this->isBase64Encoded) {
            $content = Base64::decode($content, true);
        }
        $this->statement = MetadataStatement::createFromString($content);
    }
}
