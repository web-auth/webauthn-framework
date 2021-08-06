<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use function in_array;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use function Safe\sprintf;

class StatusReport implements JsonSerializable
{
    /**
     * @see AuthenticatorStatus
     */
    private string $status;

    public function __construct(string $status, private ?string $effectiveDate, private ?string $certificate, private ?string $url, private ?string $certificationDescriptor, private ?string $certificateNumber, private ?string $certificationPolicyVersion, private ?string $certificationRequirementsVersion)
    {
        Assertion::inArray($status, AuthenticatorStatus::list(), Utils::logicException('The value of the key "status" is not acceptable'));

        $this->status = $status;
    }

    #[Pure]
    public function isCompromised(): bool
    {
        return in_array($this->status, [
            AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE,
            AuthenticatorStatus::USER_KEY_PHYSICAL_COMPROMISE,
            AuthenticatorStatus::USER_KEY_REMOTE_COMPROMISE,
            AuthenticatorStatus::USER_VERIFICATION_BYPASS,
        ], true);
    }

    #[Pure]
    public function getStatus(): string
    {
        return $this->status;
    }

    #[Pure]
    public function getEffectiveDate(): ?string
    {
        return $this->effectiveDate;
    }

    #[Pure]
    public function getCertificate(): ?string
    {
        return $this->certificate;
    }

    #[Pure]
    public function getUrl(): ?string
    {
        return $this->url;
    }

    #[Pure]
    public function getCertificationDescriptor(): ?string
    {
        return $this->certificationDescriptor;
    }

    #[Pure]
    public function getCertificateNumber(): ?string
    {
        return $this->certificateNumber;
    }

    #[Pure]
    public function getCertificationPolicyVersion(): ?string
    {
        return $this->certificationPolicyVersion;
    }

    #[Pure]
    public function getCertificationRequirementsVersion(): ?string
    {
        return $this->certificationRequirementsVersion;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        Assertion::keyExists($data, 'status', Utils::logicException('The key "status" is missing'));
        foreach (['effectiveDate', 'certificate', 'url', 'certificationDescriptor', 'certificateNumber', 'certificationPolicyVersion', 'certificationRequirementsVersion'] as $key) {
            if (isset($data[$key])) {
                Assertion::nullOrString($data[$key], Utils::logicException(sprintf('The value of the key "%s" is invalid', $key)));
            }
        }

        return new self(
            $data['status'],
            $data['effectiveDate'] ?? null,
            $data['certificate'] ?? null,
            $data['url'] ?? null,
            $data['certificationDescriptor'] ?? null,
            $data['certificateNumber'] ?? null,
            $data['certificationPolicyVersion'] ?? null,
            $data['certificationRequirementsVersion'] ?? null
        );
    }

    #[Pure]
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

        return Utils::filterNullValues($data);
    }
}
