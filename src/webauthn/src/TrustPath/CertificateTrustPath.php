<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use Throwable;

final readonly class CertificateTrustPath implements TrustPath
{
    private const OID_FIDO_GEN_CE_SERNUM = '1.3.6.1.4.1.45724.1.1.2';

    /**
     * @param string[] $certificates
     */
    public function __construct(
        public array $certificates
    ) {
    }

    /**
     * @param string[] $certificates
     */
    public static function create(array $certificates): self
    {
        return new self($certificates);
    }

    /**
     * Returns the serial number that an enterprise attestation gives the authenticator in the extension
     * id-fido-gen-ce-sernum of the attestation certificate, the first of the path. It is unique per authenticator for
     * a given AAGUID only. Returns null when that certificate does not carry the extension, or carries it marked
     * critical or with a value that is not an OCTET STRING. Before 1.6.2, pki-framework reports some decoding failures
     * with other exceptions than DecodeException.
     *
     * @see https://www.w3.org/TR/webauthn-3/#sctn-enterprise-packed-attestation-cert-requirements
     */
    public function authenticatorSerialNumber(): ?string
    {
        $attestationCertificate = $this->certificates[0] ?? null;
        if ($attestationCertificate === null) {
            return null;
        }
        $extensions = Certificate::fromPEM(PEM::fromString($attestationCertificate))
            ->tbsCertificate()
            ->extensions();
        if (! $extensions->has(self::OID_FIDO_GEN_CE_SERNUM)) {
            return null;
        }
        $extension = $extensions->get(self::OID_FIDO_GEN_CE_SERNUM);
        if ($extension->isCritical() || ! $extension instanceof UnknownExtension) {
            return null;
        }
        try {
            $value = UnspecifiedType::fromDER($extension->extensionValue())->asElement();
        } catch (Throwable) {
            return null;
        }

        return $value instanceof OctetString ? $value->string() : null;
    }
}
