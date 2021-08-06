<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use Base64Url\Base64Url;
use function count;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use LogicException;

class MetadataTOCPayloadEntry implements JsonSerializable
{
    private ?string $aaid;

    private ?string $aaguid;

    /**
     * @var string[]
     */
    private array $attestationCertificateKeyIdentifiers = [];

    private ?string $hash;

    /**
     * @var StatusReport[]
     */
    private array $statusReports = [];

    public function __construct(?string $aaid, ?string $aaguid, array $attestationCertificateKeyIdentifiers, ?string $hash, private ?string $url, private string $timeOfLastStatusChange, private ?string $rogueListURL, private ?string $rogueListHash)
    {
        if (null !== $aaid && null !== $aaguid) {
            throw new LogicException('Authenticators cannot support both AAID and AAGUID');
        }
        if (null === $aaid && null === $aaguid && 0 === count($attestationCertificateKeyIdentifiers)) {
            throw new LogicException('If neither AAID nor AAGUID are set, the attestation certificate identifier list shall not be empty');
        }
        foreach ($attestationCertificateKeyIdentifiers as $attestationCertificateKeyIdentifier) {
            Assertion::string($attestationCertificateKeyIdentifier, Utils::logicException('Invalid attestation certificate identifier. Shall be a list of strings'));
            Assertion::notEmpty($attestationCertificateKeyIdentifier, Utils::logicException('Invalid attestation certificate identifier. Shall be a list of strings'));
            Assertion::regex($attestationCertificateKeyIdentifier, '/^[0-9a-f]+$/', Utils::logicException('Invalid attestation certificate identifier. Shall be a list of strings'));
        }
        $this->aaid = $aaid;
        $this->aaguid = $aaguid;
        $this->attestationCertificateKeyIdentifiers = $attestationCertificateKeyIdentifiers;
        $this->hash = Base64Url::decode($hash);
    }

    #[Pure]
    public function getAaid(): ?string
    {
        return $this->aaid;
    }

    #[Pure]
    public function getAaguid(): ?string
    {
        return $this->aaguid;
    }

    #[Pure]
    public function getAttestationCertificateKeyIdentifiers(): array
    {
        return $this->attestationCertificateKeyIdentifiers;
    }

    #[Pure]
    public function getHash(): ?string
    {
        return $this->hash;
    }

    #[Pure]
    public function getUrl(): ?string
    {
        return $this->url;
    }

    public function addStatusReports(StatusReport $statusReport): self
    {
        $this->statusReports[] = $statusReport;

        return $this;
    }

    /**
     * @return StatusReport[]
     */
    #[Pure]
    public function getStatusReports(): array
    {
        return $this->statusReports;
    }

    #[Pure]
    public function getTimeOfLastStatusChange(): string
    {
        return $this->timeOfLastStatusChange;
    }

    #[Pure]
    public function getRogueListURL(): string
    {
        return $this->rogueListURL;
    }

    #[Pure]
    public function getRogueListHash(): string
    {
        return $this->rogueListHash;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        Assertion::keyExists($data, 'timeOfLastStatusChange', Utils::logicException('Invalid data. The parameter "timeOfLastStatusChange" is missing'));
        Assertion::keyExists($data, 'statusReports', Utils::logicException('Invalid data. The parameter "statusReports" is missing'));
        Assertion::isArray($data['statusReports'], Utils::logicException('Invalid data. The parameter "statusReports" shall be an array of StatusReport objects'));
        $object = new self(
        $data['aaid'] ?? null,
        $data['aaguid'] ?? null,
        $data['attestationCertificateKeyIdentifiers'] ?? [],
        $data['hash'] ?? null,
        $data['url'] ?? null,
            $data['timeOfLastStatusChange'],
            $data['rogueListURL'] ?? null,
            $data['rogueListHash'] ?? null
        );
        foreach ($data['statusReports'] as $statusReport) {
            $object->addStatusReports(StatusReport::createFromArray($statusReport));
        }

        return $object;
    }

    #[Pure]
    public function jsonSerialize(): array
    {
        $data = [
            'aaid' => $this->aaid,
            'aaguid' => $this->aaguid,
            'attestationCertificateKeyIdentifiers' => $this->attestationCertificateKeyIdentifiers,
            'hash' => Base64Url::encode($this->hash),
            'url' => $this->url,
            'statusReports' => array_map(static function (StatusReport $object): array {
                return $object->jsonSerialize();
            }, $this->statusReports),
            'timeOfLastStatusChange' => $this->timeOfLastStatusChange,
            'rogueListURL' => $this->rogueListURL,
            'rogueListHash' => $this->rogueListHash,
        ];

        return Utils::filterNullValues($data);
    }
}
