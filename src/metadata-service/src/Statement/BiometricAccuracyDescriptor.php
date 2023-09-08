<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Webauthn\MetadataService\Utils;

class BiometricAccuracyDescriptor extends AbstractDescriptor
{
    public function __construct(
        public readonly ?float $selfAttestedFRR,
        public readonly ?float $selfAttestedFAR,
        public readonly ?float $maxTemplates,
        ?int $maxRetries = null,
        ?int $blockSlowdown = null
    ) {
        parent::__construct($maxRetries, $blockSlowdown);
    }

    public static function create(
        ?float $selfAttestedFRR,
        ?float $selfAttestedFAR,
        ?float $maxTemplates,
        ?int $maxRetries = null,
        ?int $blockSlowdown = null
    ): self {
        return new self($selfAttestedFRR, $selfAttestedFAR, $maxTemplates, $maxRetries, $blockSlowdown);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getSelfAttestedFRR(): ?float
    {
        return $this->selfAttestedFRR;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getSelfAttestedFAR(): ?float
    {
        return $this->selfAttestedFAR;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getMaxTemplates(): ?float
    {
        return $this->maxTemplates;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        return self::create(
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
            'maxRetries' => $this->maxRetries,
            'blockSlowdown' => $this->blockSlowdown,
        ];

        return Utils::filterNullValues($data);
    }
}
