<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Webauthn\MetadataService\ValueFilter;

class BiometricAccuracyDescriptor extends AbstractDescriptor
{
    use ValueFilter;

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

        return self::filterNullValues($data);
    }
}
