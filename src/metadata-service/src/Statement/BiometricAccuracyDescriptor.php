<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Webauthn\MetadataService\Utils;

/**
 * @final
 */
class BiometricAccuracyDescriptor extends AbstractDescriptor
{
    public function __construct(
        private readonly ?float $selfAttestedFRR,
        private readonly ?float $selfAttestedFAR,
        private readonly ?float $maxTemplates,
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

    /**
     * @param array<string, mixed> $data
     */
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

    /**
     * @return array<string, mixed>
     */
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
