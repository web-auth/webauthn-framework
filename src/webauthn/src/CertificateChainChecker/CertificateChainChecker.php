<?php

declare(strict_types=1);

namespace Webauthn\CertificateChainChecker;

interface CertificateChainChecker
{
    /**
     * @param string[] $authenticatorCertificates
     * @param string[] $trustedCertificates
     */
    public function check(array $authenticatorCertificates, array $trustedCertificates): void;
}
