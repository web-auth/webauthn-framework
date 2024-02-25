<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

class BiometricStatusReport implements JsonSerializable
{
    private function __construct(
        public readonly ?int $certLevel,
        public readonly ?int $modality,
        public readonly ?string $effectiveDate,
        public readonly ?string $certificationDescriptor,
        public readonly ?string $certificateNumber,
        public readonly ?string $certificationPolicyVersion,
        public readonly ?string $certificationRequirementsVersion,
    ) {
    }

    public static function create(
        ?int $certLevel,
        ?int $modality,
        ?string $effectiveDate,
        ?string $certificationDescriptor,
        ?string $certificateNumber,
        ?string $certificationPolicyVersion,
        ?string $certificationRequirementsVersion,
    ): self {
        return new self(
            $certLevel,
            $modality,
            $effectiveDate,
            $certificationDescriptor,
            $certificateNumber,
            $certificationPolicyVersion,
            $certificationRequirementsVersion,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'certLevel' => $this->certLevel,
            'modality' => $this->modality,
            'effectiveDate' => $this->effectiveDate,
            'certificationDescriptor' => $this->certificationDescriptor,
            'certificateNumber' => $this->certificateNumber,
            'certificationPolicyVersion' => $this->certificationPolicyVersion,
            'certificationRequirementsVersion' => $this->certificationRequirementsVersion,
        ];

        return array_filter($data, static fn ($var): bool => $var !== null);
    }
}
