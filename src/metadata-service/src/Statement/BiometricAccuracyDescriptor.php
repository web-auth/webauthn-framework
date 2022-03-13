<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Webauthn\MetadataService\Utils;

class BiometricAccuracyDescriptor extends AbstractDescriptor
{
    public function __construct(
        private ?float $selfAttestedFRR,
        private ?float $selfAttestedFAR,
        private ?float $maxTemplates,
        ?int $maxRetries = null,
        ?int $blockSlowdown = null
    ) {
        parent::__construct($maxRetries, $blockSlowdown);
    }

    public function getSelfAttestedFRR(): ?float
    {
        return $this->selfAttestedFRR;
    }

    public function getSelfAttestedFAR(): ?float
    {
        return $this->selfAttestedFAR;
    }

    public function getMaxTemplates(): ?float
    {
        return $this->maxTemplates;
    }

    public static function createFromArray(array $data): self
    {
        return new self(
            $data['selfAttestedFRR'] ?? null,
            $data['selfAttestedFAR'] ?? null,
            $data['maxTemplates'] ?? null,
            $data['maxRetries'] ?? null,
            $data['blockSlowdown'] ?? null
        );
    }

    public function jsonSerialize(): array
    {
        $data = [
            'selfAttestedFRR' => $this->selfAttestedFRR,
            'selfAttestedFAR' => $this->selfAttestedFAR,
            'maxTemplates' => $this->maxTemplates,
            'maxRetries' => $this->getMaxRetries(),
            'blockSlowdown' => $this->getBlockSlowdown(),
        ];

        return Utils::filterNullValues($data);
    }
}
