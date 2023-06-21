<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function array_key_exists;
use function is_array;
use function is_string;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;

/**
 * @final
 */
class MetadataStatement implements JsonSerializable
{
    final public const KEY_PROTECTION_SOFTWARE = 'software';

    final public const KEY_PROTECTION_HARDWARE = 'hardware';

    final public const KEY_PROTECTION_TEE = 'tee';

    final public const KEY_PROTECTION_SECURE_ELEMENT = 'secure_element';

    final public const KEY_PROTECTION_REMOTE_HANDLE = 'remote_handle';

    final public const MATCHER_PROTECTION_SOFTWARE = 'software';

    final public const MATCHER_PROTECTION_TEE = 'tee';

    final public const MATCHER_PROTECTION_ON_CHIP = 'on_chip';

    final public const ATTACHMENT_HINT_INTERNAL = 'internal';

    final public const ATTACHMENT_HINT_EXTERNAL = 'external';

    final public const ATTACHMENT_HINT_WIRED = 'wired';

    final public const ATTACHMENT_HINT_WIRELESS = 'wireless';

    final public const ATTACHMENT_HINT_NFC = 'nfc';

    final public const ATTACHMENT_HINT_BLUETOOTH = 'bluetooth';

    final public const ATTACHMENT_HINT_NETWORK = 'network';

    final public const ATTACHMENT_HINT_READY = 'ready';

    final public const ATTACHMENT_HINT_WIFI_DIRECT = 'wifi_direct';

    final public const TRANSACTION_CONFIRMATION_DISPLAY_ANY = 'any';

    final public const TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE = 'privileged_software';

    final public const TRANSACTION_CONFIRMATION_DISPLAY_TEE = 'tee';

    final public const TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE = 'hardware';

    final public const TRANSACTION_CONFIRMATION_DISPLAY_REMOTE = 'remote';

    final public const ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW = 'secp256r1_ecdsa_sha256_raw';

    final public const ALG_SIGN_SECP256R1_ECDSA_SHA256_DER = 'secp256r1_ecdsa_sha256_der';

    final public const ALG_SIGN_RSASSA_PSS_SHA256_RAW = 'rsassa_pss_sha256_raw';

    final public const ALG_SIGN_RSASSA_PSS_SHA256_DER = 'rsassa_pss_sha256_der';

    final public const ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW = 'secp256k1_ecdsa_sha256_raw';

    final public const ALG_SIGN_SECP256K1_ECDSA_SHA256_DER = 'secp256k1_ecdsa_sha256_der';

    final public const ALG_SIGN_SM2_SM3_RAW = 'sm2_sm3_raw';

    final public const ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW = 'rsa_emsa_pkcs1_sha256_raw';

    final public const ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER = 'rsa_emsa_pkcs1_sha256_der';

    final public const ALG_SIGN_RSASSA_PSS_SHA384_RAW = 'rsassa_pss_sha384_raw';

    final public const ALG_SIGN_RSASSA_PSS_SHA512_RAW = 'rsassa_pss_sha256_raw';

    final public const ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW = 'rsassa_pkcsv15_sha256_raw';

    final public const ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW = 'rsassa_pkcsv15_sha384_raw';

    final public const ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW = 'rsassa_pkcsv15_sha512_raw';

    final public const ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW = 'rsassa_pkcsv15_sha1_raw';

    final public const ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW = 'secp384r1_ecdsa_sha384_raw';

    final public const ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW = 'secp512r1_ecdsa_sha256_raw';

    final public const ALG_SIGN_ED25519_EDDSA_SHA256_RAW = 'ed25519_eddsa_sha512_raw';

    final public const ALG_KEY_ECC_X962_RAW = 'ecc_x962_raw';

    final public const ALG_KEY_ECC_X962_DER = 'ecc_x962_der';

    final public const ALG_KEY_RSA_2048_RAW = 'rsa_2048_raw';

    final public const ALG_KEY_RSA_2048_DER = 'rsa_2048_der';

    final public const ALG_KEY_COSE = 'cose';

    final public const ATTESTATION_BASIC_FULL = 'basic_full';

    final public const ATTESTATION_BASIC_SURROGATE = 'basic_surrogate';

    /**
     * @deprecated since 4.2.0 and will be removed in 5.0.0. The ECDAA Trust Anchor does no longer exist in Webauthn specification.
     */
    final public const ATTESTATION_ECDAA = 'ecdaa';

    final public const ATTESTATION_ATTCA = 'attca';

    final public const ATTESTATION_ANONCA = 'anonca';

    private ?string $legalHeader = null;

    private ?string $aaid = null;

    private ?string $aaguid = null;

    /**
     * @var string[]
     */
    private array $attestationCertificateKeyIdentifiers = [];

    private AlternativeDescriptions $alternativeDescriptions;

    /**
     * @var string[]
     */
    private array $keyProtection = [];

    private ?bool $isKeyRestricted = null;

    private ?bool $isFreshUserVerificationRequired = null;

    private ?int $cryptoStrength = null;

    /**
     * @var string[]
     */
    private array $attachmentHint = [];

    private ?string $tcDisplayContentType = null;

    /**
     * @var DisplayPNGCharacteristicsDescriptor[]
     */
    private array $tcDisplayPNGCharacteristics = [];

    /**
     * @var EcdaaTrustAnchor[]
     */
    private array $ecdaaTrustAnchors = [];

    private ?string $icon = null;

    /**
     * @var ExtensionDescriptor[]
     */
    private array $supportedExtensions = [];

    private null|AuthenticatorGetInfo $authenticatorGetInfo = null;

    /**
     * @param Version[] $upv
     * @param string[] $authenticationAlgorithms
     * @param string[] $publicKeyAlgAndEncodings
     * @param string[] $attestationTypes
     * @param VerificationMethodANDCombinations[] $userVerificationDetails
     * @param string[] $matcherProtection
     * @param string[] $tcDisplay
     * @param string[] $attestationRootCertificates
     */
    public function __construct(
        private readonly string $description,
        private readonly int $authenticatorVersion,
        private readonly string $protocolFamily,
        private readonly int $schema,
        private readonly array $upv,
        private readonly array $authenticationAlgorithms,
        private readonly array $publicKeyAlgAndEncodings,
        private readonly array $attestationTypes,
        private readonly array $userVerificationDetails,
        private readonly array $matcherProtection,
        private readonly array $tcDisplay,
        private readonly array $attestationRootCertificates,
    ) {
        $this->alternativeDescriptions = new AlternativeDescriptions();
        $this->authenticatorGetInfo = new AuthenticatorGetInfo();
    }

    public static function createFromString(string $statement): self
    {
        $data = json_decode($statement, true, 512, JSON_THROW_ON_ERROR);

        return self::createFromArray($data);
    }

    public function getLegalHeader(): ?string
    {
        return $this->legalHeader;
    }

    public function getAaid(): ?string
    {
        return $this->aaid;
    }

    public function getAaguid(): ?string
    {
        return $this->aaguid;
    }

    public function isKeyRestricted(): ?bool
    {
        return $this->isKeyRestricted;
    }

    public function isFreshUserVerificationRequired(): ?bool
    {
        return $this->isFreshUserVerificationRequired;
    }

    public function getAuthenticatorGetInfo(): AuthenticatorGetInfo|null
    {
        return $this->authenticatorGetInfo;
    }

    /**
     * @return string[]
     */
    public function getAttestationCertificateKeyIdentifiers(): array
    {
        return $this->attestationCertificateKeyIdentifiers;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getAlternativeDescriptions(): AlternativeDescriptions
    {
        return $this->alternativeDescriptions;
    }

    public function getAuthenticatorVersion(): int
    {
        return $this->authenticatorVersion;
    }

    public function getProtocolFamily(): string
    {
        return $this->protocolFamily;
    }

    /**
     * @return Version[]
     */
    public function getUpv(): array
    {
        return $this->upv;
    }

    public function getSchema(): ?int
    {
        return $this->schema;
    }

    /**
     * @return string[]
     */
    public function getAuthenticationAlgorithms(): array
    {
        return $this->authenticationAlgorithms;
    }

    /**
     * @return string[]
     */
    public function getPublicKeyAlgAndEncodings(): array
    {
        return $this->publicKeyAlgAndEncodings;
    }

    /**
     * @return string[]
     */
    public function getAttestationTypes(): array
    {
        return $this->attestationTypes;
    }

    /**
     * @return VerificationMethodANDCombinations[]
     */
    public function getUserVerificationDetails(): array
    {
        return $this->userVerificationDetails;
    }

    /**
     * @return string[]
     */
    public function getKeyProtection(): array
    {
        return $this->keyProtection;
    }

    /**
     * @return string[]
     */
    public function getMatcherProtection(): array
    {
        return $this->matcherProtection;
    }

    public function getCryptoStrength(): ?int
    {
        return $this->cryptoStrength;
    }

    /**
     * @return string[]
     */
    public function getAttachmentHint(): array
    {
        return $this->attachmentHint;
    }

    /**
     * @return string[]
     */
    public function getTcDisplay(): array
    {
        return $this->tcDisplay;
    }

    public function getTcDisplayContentType(): ?string
    {
        return $this->tcDisplayContentType;
    }

    /**
     * @return DisplayPNGCharacteristicsDescriptor[]
     */
    public function getTcDisplayPNGCharacteristics(): array
    {
        return $this->tcDisplayPNGCharacteristics;
    }

    /**
     * @return string[]
     */
    public function getAttestationRootCertificates(): array
    {
        return $this->attestationRootCertificates;
    }

    /**
     * @return EcdaaTrustAnchor[]
     *
     * @deprecated since 4.2.0 and will be removed in 5.0.0. The ECDAA Trust Anchor does no longer exist in Webauthn specification.
     */
    public function getEcdaaTrustAnchors(): array
    {
        return $this->ecdaaTrustAnchors;
    }

    public function getIcon(): ?string
    {
        return $this->icon;
    }

    /**
     * @return ExtensionDescriptor[]
     */
    public function getSupportedExtensions(): array
    {
        return $this->supportedExtensions;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $requiredKeys = [
            'description',
            'authenticatorVersion',
            'protocolFamily',
            'schema',
            'upv',
            'authenticationAlgorithms',
            'publicKeyAlgAndEncodings',
            'attestationTypes',
            'userVerificationDetails',
            'matcherProtection',
            'tcDisplay',
            'attestationRootCertificates',
        ];
        foreach ($requiredKeys as $key) {
            array_key_exists($key, $data) || throw MetadataStatementLoadingException::create(sprintf(
                'Invalid data. The key "%s" is missing',
                $key
            ));
        }
        $subObjects = [
            'authenticationAlgorithms',
            'publicKeyAlgAndEncodings',
            'attestationTypes',
            'matcherProtection',
            'tcDisplay',
            'attestationRootCertificates',
        ];
        foreach ($subObjects as $subObject) {
            is_array($data[$subObject]) || throw MetadataStatementLoadingException::create(sprintf(
                'Invalid Metadata Statement. The parameter "%s" shall be a list of strings.',
                $subObject
            ));
            foreach ($data[$subObject] as $datum) {
                is_string($datum) || throw MetadataStatementLoadingException::create(sprintf(
                    'Invalid Metadata Statement. The parameter "%s" shall be a list of strings.',
                    $subObject
                ));
            }
        }

        $object = new self(
            $data['description'],
            $data['authenticatorVersion'],
            $data['protocolFamily'],
            $data['schema'],
            array_map(static function ($upv): Version {
                is_array($upv) || throw MetadataStatementLoadingException::create('Invalid Metadata Statement');

                return Version::createFromArray($upv);
            }, $data['upv']),
            $data['authenticationAlgorithms'],
            $data['publicKeyAlgAndEncodings'],
            $data['attestationTypes'],
            array_map(static function ($userVerificationDetails): VerificationMethodANDCombinations {
                is_array($userVerificationDetails) || throw MetadataStatementLoadingException::create(
                    'Invalid Metadata Statement'
                );

                return VerificationMethodANDCombinations::createFromArray($userVerificationDetails);
            }, $data['userVerificationDetails']),
            $data['matcherProtection'],
            $data['tcDisplay'],
            CertificateToolbox::fixPEMStructures($data['attestationRootCertificates'])
        );

        $object->legalHeader = $data['legalHeader'] ?? null;
        $object->aaid = $data['aaid'] ?? null;
        $object->aaguid = $data['aaguid'] ?? null;
        $object->attestationCertificateKeyIdentifiers = $data['attestationCertificateKeyIdentifiers'] ?? [];
        $object->alternativeDescriptions = AlternativeDescriptions::create($data['alternativeDescriptions'] ?? []);
        $object->authenticatorGetInfo = isset($data['attestationTypes']) ? AuthenticatorGetInfo::create(
            $data['attestationTypes']
        ) : null;
        $object->keyProtection = $data['keyProtection'] ?? [];
        $object->isKeyRestricted = $data['isKeyRestricted'] ?? null;
        $object->isFreshUserVerificationRequired = $data['isFreshUserVerificationRequired'] ?? null;
        $object->cryptoStrength = $data['cryptoStrength'] ?? null;
        $object->attachmentHint = $data['attachmentHint'] ?? [];
        $object->tcDisplayContentType = $data['tcDisplayContentType'] ?? null;
        if (isset($data['tcDisplayPNGCharacteristics'])) {
            $tcDisplayPNGCharacteristics = $data['tcDisplayPNGCharacteristics'];
            is_array($tcDisplayPNGCharacteristics) || throw MetadataStatementLoadingException::create(
                'Invalid Metadata Statement'
            );
            foreach ($tcDisplayPNGCharacteristics as $tcDisplayPNGCharacteristic) {
                is_array($tcDisplayPNGCharacteristic) || throw MetadataStatementLoadingException::create(
                    'Invalid Metadata Statement'
                );
                $object->tcDisplayPNGCharacteristics[] = DisplayPNGCharacteristicsDescriptor::createFromArray(
                    $tcDisplayPNGCharacteristic
                );
            }
        }
        $object->ecdaaTrustAnchors = $data['ecdaaTrustAnchors'] ?? [];
        $object->icon = $data['icon'] ?? null;
        if (isset($data['supportedExtensions'])) {
            $supportedExtensions = $data['supportedExtensions'];
            is_array($supportedExtensions) || throw MetadataStatementLoadingException::create(
                'Invalid Metadata Statement'
            );
            foreach ($supportedExtensions as $supportedExtension) {
                is_array($supportedExtension) || throw MetadataStatementLoadingException::create(
                    'Invalid Metadata Statement'
                );
                $object->supportedExtensions[] = ExtensionDescriptor::createFromArray($supportedExtension);
            }
        }

        return $object;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'legalHeader' => $this->legalHeader,
            'aaid' => $this->aaid,
            'aaguid' => $this->aaguid,
            'attestationCertificateKeyIdentifiers' => $this->attestationCertificateKeyIdentifiers,
            'description' => $this->description,
            'alternativeDescriptions' => $this->alternativeDescriptions,
            'authenticatorVersion' => $this->authenticatorVersion,
            'protocolFamily' => $this->protocolFamily,
            'upv' => $this->upv,
            'authenticationAlgorithms' => $this->authenticationAlgorithms,
            'publicKeyAlgAndEncodings' => $this->publicKeyAlgAndEncodings,
            'attestationTypes' => $this->attestationTypes,
            'userVerificationDetails' => $this->userVerificationDetails,
            'keyProtection' => $this->keyProtection,
            'isKeyRestricted' => $this->isKeyRestricted,
            'isFreshUserVerificationRequired' => $this->isFreshUserVerificationRequired,
            'matcherProtection' => $this->matcherProtection,
            'cryptoStrength' => $this->cryptoStrength,
            'attachmentHint' => $this->attachmentHint,
            'tcDisplay' => $this->tcDisplay,
            'tcDisplayContentType' => $this->tcDisplayContentType,
            'tcDisplayPNGCharacteristics' => array_map(
                static fn (DisplayPNGCharacteristicsDescriptor $object): array => $object->jsonSerialize(),
                $this->tcDisplayPNGCharacteristics
            ),
            'attestationRootCertificates' => CertificateToolbox::fixPEMStructures($this->attestationRootCertificates),
            'ecdaaTrustAnchors' => array_map(
                static fn (EcdaaTrustAnchor $object): array => $object->jsonSerialize(),
                $this->ecdaaTrustAnchors
            ),
            'icon' => $this->icon,
            'authenticatorGetInfo' => $this->authenticatorGetInfo,
            'supportedExtensions' => array_map(
                static fn (ExtensionDescriptor $object): array => $object->jsonSerialize(),
                $this->supportedExtensions
            ),
        ];

        return Utils::filterNullValues($data);
    }
}
