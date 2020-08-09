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

use function array_key_exists;
use Assert\Assertion;
use Assert\AssertionFailedException;

class ExtendedMetadataStatement extends MetadataStatement
{
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

    /**
     * @throws AssertionFailedException
     */
    public static function createFromArray(array $data): MetadataStatement
    {
        $object = self::createFromMetadataStatement(parent::createFromArray($data));
        if (!array_key_exists('extended', $data)) {
            return $object;
        }

        if (array_key_exists('rootCertificates', $data['extended'])) {
            Assertion::isArray($data['extended']['rootCertificates'], 'Invalid data');
            Assertion::allString($data['extended']['rootCertificates'], 'Invalid data');
            $object->setRootCertificates($data['extended']['rootCertificates']);
        }

        if (array_key_exists('rootCertificates', $data['extended'])) {
            Assertion::isArray($data['extended']['rootCertificates'], 'Invalid data');
            Assertion::allString($data['extended']['rootCertificates'], 'Invalid data');
            $object->setRootCertificates($data['extended']['rootCertificates']);
        }

        if (array_key_exists('statusReports', $data['extended'])) {
            Assertion::isArray($data['extended']['statusReports'], 'Invalid data');
            $reports = [];
            foreach ($data['extended']['statusReports'] as $report) {
                $reports[] = StatusReport::createFromArray($report);
            }
            $object->setStatusReports($reports);
        }

        return $object;
    }

    public function jsonSerialize(): array
    {
        $data = parent::jsonSerialize();
        $data['extended'] = [
            'rootCertificates' => $this->rootCertificates,
            'statusReports' => array_map(static function (StatusReport $object): array {
                return $object->jsonSerialize();
            }, $this->statusReports),
        ];

        return $data;
    }
}
