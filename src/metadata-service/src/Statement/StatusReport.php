<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\ValueFilter;
use function in_array;

class StatusReport implements JsonSerializable
{
    use ValueFilter;

    /**
     * @see AuthenticatorStatus
     */
    public function __construct(
        public readonly string $status,
        public readonly ?string $effectiveDate,
        public readonly ?string $certificate,
        public readonly ?string $url,
        public readonly ?string $certificationDescriptor,
        public readonly ?string $certificateNumber,
        public readonly ?string $certificationPolicyVersion,
        public readonly ?string $certificationRequirementsVersion
    ) {
        in_array($status, AuthenticatorStatus::STATUSES, true) || throw MetadataStatementLoadingException::create(
            'The value of the key "status" is not acceptable'
        );
    }

    public static function create(
        string $status,
        ?string $effectiveDate,
        ?string $certificate,
        ?string $url,
        ?string $certificationDescriptor,
        ?string $certificateNumber,
        ?string $certificationPolicyVersion,
        ?string $certificationRequirementsVersion
    ): self {
        return new self(
            $status,
            $effectiveDate,
            $certificate,
            $url,
            $certificationDescriptor,
            $certificateNumber,
            $certificationPolicyVersion,
            $certificationRequirementsVersion
        );
    }

    public function isCompromised(): bool
    {
        return in_array($this->status, [
            AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE,
            AuthenticatorStatus::USER_KEY_PHYSICAL_COMPROMISE,
            AuthenticatorStatus::USER_KEY_REMOTE_COMPROMISE,
            AuthenticatorStatus::USER_VERIFICATION_BYPASS,
        ], true);
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'status' => $this->status,
            'effectiveDate' => $this->effectiveDate,
            'certificate' => $this->certificate,
            'url' => $this->url,
            'certificationDescriptor' => $this->certificationDescriptor,
            'certificateNumber' => $this->certificateNumber,
            'certificationPolicyVersion' => $this->certificationPolicyVersion,
            'certificationRequirementsVersion' => $this->certificationRequirementsVersion,
        ];

        return self::filterNullValues($data);
    }
}
