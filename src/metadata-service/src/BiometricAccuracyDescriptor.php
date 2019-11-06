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

use Assert\Assertion;
use LogicException;

class BiometricAccuracyDescriptor extends AbstractDescriptor
{
    /**
     * @var float|null
     */
    private $FAR;

    /**
     * @var float|null
     */
    private $FRR;

    /**
     * @var float|null
     */
    private $EER;

    /**
     * @var float|null
     */
    private $FAAR;

    /**
     * @var int|null
     */
    private $maxReferenceDataSets;

    public function __construct(?float $FAR, ?float $FRR, ?float $EER, ?float $FAAR, ?int $maxReferenceDataSets, ?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        if (null === $FAR && null === $FRR && null === $EER && null === $FAAR) {
            throw new LogicException('Invalid data. Must contain at least one item');
        }
        Assertion::greaterOrEqualThan($maxReferenceDataSets, 0, Utils::logicException('Invalid data. The value of "maxReferenceDataSets" must be a positive integer'));

        $this->FRR = $FRR;
        $this->FAR = $FAR;
        $this->EER = $EER;
        $this->FAAR = $FAAR;
        $this->maxReferenceDataSets = $maxReferenceDataSets;
        parent::__construct($maxRetries, $blockSlowdown);
    }

    /**
     * @return float|null
     */
    public function getFAR(): ?float
    {
        return $this->FAR;
    }

    /**
     * @return float|null
     */
    public function getFRR(): ?float
    {
        return $this->FRR;
    }

    /**
     * @return float|null
     */
    public function getEER(): ?float
    {
        return $this->EER;
    }

    /**
     * @return float|null
     */
    public function getFAAR(): ?float
    {
        return $this->FAAR;
    }

    /**
     * @return int|null
     */
    public function getMaxReferenceDataSets(): ?int
    {
        return $this->maxReferenceDataSets;
    }

    public static function createFromArray(array $data): self
    {
        return new self(
            $data['FAR'] ?? null,
            $data['FRR'] ?? null,
            $data['EER'] ?? null,
            $data['FAAR'] ?? null,
            $data['maxReferenceDataSets'] ?? null,
            $data['maxRetries'] ?? null,
            $data['blockSlowdown'] ?? null
        );
    }

    public function jsonSerialize(): array
    {
        $data = [
            'FAR' => $this->FAR,
            'FRR' => $this->FRR,
            'EER' => $this->EER,
            'FAAR' => $this->FAAR,
            'maxReferenceDataSets' => $this->maxReferenceDataSets,
            'maxRetries' => $this->getMaxRetries(),
            'blockSlowdown' => $this->getBlockSlowdown(),
        ];

        return Utils::filterNullValues($data);
    }
}
