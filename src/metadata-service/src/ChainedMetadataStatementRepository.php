<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

class ChainedMetadataStatementRepository implements MetadataStatementRepository
{
    /**
     * @var MetadataStatementRepository[]
     */
    private array $repositories;

    public function __construct(MetadataStatementRepository ...$repositories)
    {
        $this->repositories = $repositories;
    }

    public function add(MetadataStatementRepository $repository): self
    {
        $this->repositories[] = $repository;

        return $this;
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        foreach ($this->repositories as $repository) {
            $mds = $repository->findOneByAAGUID($aaguid);
            if ($mds !== null) {
                return $mds;
            }
        }

        return null;
    }
}
