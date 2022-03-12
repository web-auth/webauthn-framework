<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;

class BiometricAccuracyDescriptor extends AbstractDescriptor
{
    private ?int $maxReferenceDataSets;

    public function __construct(private ?float $FAR, private ?float $FRR, private ?float $EER, private ?float $FAAR, ?int $maxReferenceDataSets, ?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        Assertion::greaterOrEqualThan($maxReferenceDataSets, 0, Utils::logicException('Invalid data. The value of "maxReferenceDataSets" must be a positive integer'));
        $this->maxReferenceDataSets = $maxReferenceDataSets;
        parent::__construct($maxRetries, $blockSlowdown);
    }

    
    public function getFAR(): ?float
    {
        return $this->FAR;
    }

    
    public function getFRR(): ?float
    {
        return $this->FRR;
    }

    
    public function getEER(): ?float
    {
        return $this->EER;
    }

    
    public function getFAAR(): ?float
    {
        return $this->FAAR;
    }

    
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
