<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use function count;
use JsonSerializable;
use LogicException;
use ParagonIE\ConstantTime\Base64UrlSafe;

class MetadataTOCPayloadEntry implements JsonSerializable
{
    private ?string $aaid;

    private ?string $aaguid;

    /**
     * @var string[]
     */
    private array $attestationCertificateKeyIdentifiers = [];

    private ?string $hash = null;

    /**
     * @var StatusReport[]
     */
    private array $statusReports = [];

    public function __construct(
        ?string $aaid,
        ?string $aaguid,
        array $attestationCertificateKeyIdentifiers,
        ?string $hash,
        private ?string $url,
        private string $timeOfLastStatusChange,
        private ?string $rogueListURL,
        private ?string $rogueListHash
    ) {
        if ($aaid !== null && $aaguid !== null) {
            throw new LogicException('Authenticators cannot support both AAID and AAGUID');
        }
        if ($aaid === null && $aaguid === null && count($attestationCertificateKeyIdentifiers) === 0) {
            throw new LogicException(
                'If neither AAID nor AAGUID are set, the attestation certificate identifier list shall not be empty'
            );
        }
        foreach ($attestationCertificateKeyIdentifiers as $attestationCertificateKeyIdentifier) {
            Assertion::string(
                $attestationCertificateKeyIdentifier,
                Utils::logicException('Invalid attestation certificate identifier. Shall be a list of strings')
            );
            Assertion::notEmpty(
                $attestationCertificateKeyIdentifier,
                Utils::logicException('Invalid attestation certificate identifier. Shall be a list of strings')
            );
            Assertion::regex(
                $attestationCertificateKeyIdentifier,
                '/^[0-9a-f]+$/',
                Utils::logicException('Invalid attestation certificate identifier. Shall be a list of strings')
            );
        }
        $this->aaid = $aaid;
        $this->aaguid = $aaguid;
        $this->attestationCertificateKeyIdentifiers = $attestationCertificateKeyIdentifiers;
        $this->hash = Base64UrlSafe::decode($hash);
    }

    public function getAaid(): ?string
    {
        return $this->aaid;
    }

    public function getAaguid(): ?string
    {
        return $this->aaguid;
    }

    public function getAttestationCertificateKeyIdentifiers(): array
    {
        return $this->attestationCertificateKeyIdentifiers;
    }

    public function getHash(): ?string
    {
        return $this->hash;
    }

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
    public function getStatusReports(): array
    {
        return $this->statusReports;
    }

    public function getTimeOfLastStatusChange(): string
    {
        return $this->timeOfLastStatusChange;
    }

    public function getRogueListURL(): string
    {
        return $this->rogueListURL;
    }

    public function getRogueListHash(): string
    {
        return $this->rogueListHash;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        Assertion::keyExists(
            $data,
            'timeOfLastStatusChange',
            Utils::logicException('Invalid data. The parameter "timeOfLastStatusChange" is missing')
        );
        Assertion::keyExists(
            $data,
            'statusReports',
            Utils::logicException('Invalid data. The parameter "statusReports" is missing')
        );
        Assertion::isArray(
            $data['statusReports'],
            Utils::logicException(
                'Invalid data. The parameter "statusReports" shall be an array of StatusReport objects'
            )
        );
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

    public function jsonSerialize(): array
    {
        $data = [
            'aaid' => $this->aaid,
            'aaguid' => $this->aaguid,
            'attestationCertificateKeyIdentifiers' => $this->attestationCertificateKeyIdentifiers,
            'hash' => Base64UrlSafe::encodeUnpadded($this->hash),
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
