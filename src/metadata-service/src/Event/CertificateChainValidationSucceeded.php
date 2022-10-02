<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Event;

class CertificateChainValidationSucceeded implements WebauthnEvent
{
    public function __construct(
        public readonly array $untrustedCertificates,
        public readonly string $trustedCertificate
    ) {
    }

    public static function create(array $untrustedCertificates, string $trustedCertificate): self
    {
        return new self($untrustedCertificates, $trustedCertificate);
    }
}
