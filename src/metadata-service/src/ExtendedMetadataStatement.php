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

class ExtendedMetadataStatement extends MetadataStatement
{
    /**
     * @var string[]
     */
    private $crls = [];

    /**
     * @var string[]
     */
    private $rootCertificates = [];

    /**
     * @var StatusReport[]
     */
    private $statusReports = [];

    /**
     * @return string[]
     */
    public function getCrls(): array
    {
        return $this->crls;
    }

    /**
     * @param string[] $crls
     */
    public function setCrls(array $crls): self
    {
        $this->crls = $crls;

        return $this;
    }

    /**
     * @return string[]
     */
    public function getRootCertificates(): array
    {
        return $this->rootCertificates;
    }

    /**
     * @param string[] $rootCertificates
     */
    public function setRootCertificates(array $rootCertificates): self
    {
        $this->rootCertificates = $rootCertificates;

        return $this;
    }

    /**
     * @return StatusReport[]
     */
    public function getStatusReports(): array
    {
        return $this->statusReports;
    }

    /**
     * @param StatusReport[] $statusReports
     */
    public function setStatusReports(array $statusReports): self
    {
        $this->statusReports = $statusReports;

        return $this;
    }

    public static function createFromMetadataStatement(MetadataStatement $metadataStatement): self
    {
        $objet = new self();
        $properties = get_class_vars(MetadataStatement::class);
        foreach ($properties as $property) {
            $objet->{$property} = $metadataStatement->{$property};
        }

        return $objet;
    }
}
