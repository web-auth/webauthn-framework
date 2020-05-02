<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use Assert\Assertion;
use InvalidArgumentException;
use Symfony\Component\Process\Process;

class CertificateToolbox
{
    /**
     * @param array<string> $authenticatorCertificates
     * @param array<string> $trustedCertificates
     */
    public static function checkChain(array $authenticatorCertificates, array $trustedCertificates = []): void
    {
        self::checkCertificatesValidity($authenticatorCertificates);
        self::checkCertificatesValidity($trustedCertificates);

        if (0 === \count($trustedCertificates)) {
            return;
        }
        $filenames = [];

        $leafFilename = tempnam(sys_get_temp_dir(), 'webauthn-leaf-');
        Assertion::string($leafFilename, 'Unable to get a temporary filename');

        $leafCertificate = array_shift($authenticatorCertificates);
        $result = file_put_contents($leafFilename, $leafCertificate);
        Assertion::integer($result, 'Unable to write temporary data');
        $filenames[] = $leafFilename;

        $processArguments = ['--no-CApath', '--no-CAfile'];

        foreach ($trustedCertificates as $certificate) {
            $trustedFilename = tempnam(sys_get_temp_dir(), 'webauthn-trusted-');
            Assertion::string($trustedFilename, 'Unable to get a temporary filename');
            $result = file_put_contents($trustedFilename, $certificate, FILE_APPEND);
            Assertion::integer($result, 'Unable to write temporary data');
            $result = file_put_contents($trustedFilename, PHP_EOL, FILE_APPEND);
            Assertion::integer($result, 'Unable to write temporary data');
            $processArguments[] = '-trusted';
            $processArguments[] = $trustedFilename;
            $filenames[] = $trustedFilename;
        }
        foreach ($authenticatorCertificates as $certificate) {
            $untrustedFilename = tempnam(sys_get_temp_dir(), 'webauthn-untrusted-');
            Assertion::string($untrustedFilename, 'Unable to get a temporary filename');
            $result = file_put_contents($untrustedFilename, $certificate, FILE_APPEND);
            Assertion::integer($result, 'Unable to write temporary data');
            $result = file_put_contents($untrustedFilename, PHP_EOL, FILE_APPEND);
            Assertion::integer($result, 'Unable to write temporary data');
            $processArguments[] = '-untrusted';
            $processArguments[] = $untrustedFilename;
            $filenames[] = $untrustedFilename;
        }

        $processArguments[] = $leafFilename;
        array_unshift($processArguments, 'openssl', 'verify');

        $process = new Process($processArguments);
        $process->start();
        while ($process->isRunning()) {
        }
        foreach ($filenames as $filename) {
            $result = unlink($filename);
            Assertion::true($result, 'Unable to delete temporary file');
        }

        if (!$process->isSuccessful()) {
            throw new InvalidArgumentException('Invalid certificate or certificate chain. Error is: '.$process->getErrorOutput());
        }
    }

    public static function fixPEMStructure(string $certificate): string
    {
        $pemCert = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $pemCert .= chunk_split($certificate, 64, PHP_EOL);
        $pemCert .= '-----END CERTIFICATE-----'.PHP_EOL;

        return $pemCert;
    }

    public static function convertDERToPEM(string $certificate): string
    {
        $derCertificate = self::unusedBytesFix($certificate);

        return self::fixPEMStructure(base64_encode($derCertificate));
    }

    /**
     * @param array<string> $certificates
     *
     * @return array<string>
     */
    public static function convertAllDERToPEM(array $certificates): array
    {
        $certs = [];
        foreach ($certificates as $publicKey) {
            $certs[] = self::convertDERToPEM($publicKey);
        }

        return $certs;
    }

    private static function unusedBytesFix(string $certificate): string
    {
        $certificateHash = hash('sha256', $certificate);
        if (\in_array($certificateHash, self::getCertificateHashes(), true)) {
            $certificate[mb_strlen($certificate, '8bit') - 257] = "\0";
        }

        return $certificate;
    }

    /**
     * @param array<string> $certificates
     */
    private static function checkCertificatesValidity(array $certificates): void
    {
        foreach ($certificates as $certificate) {
            $parsed = openssl_x509_parse($certificate);
            Assertion::isArray($parsed, 'Unable to read the certificate');
            Assertion::keyExists($parsed, 'validTo_time_t', 'The certificate has no validity period');
            Assertion::keyExists($parsed, 'validFrom_time_t', 'The certificate has no validity period');
            Assertion::lessOrEqualThan(time(), $parsed['validTo_time_t'], 'The certificate expired');
            Assertion::greaterOrEqualThan(time(), $parsed['validFrom_time_t'], 'The certificate is not usable yet');
        }
    }

    /**
     * @return array<string>
     */
    private static function getCertificateHashes(): array
    {
        return [
            '349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8',
            'dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f',
            '1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae',
            'd0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb',
            '6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897',
            'ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511',
        ];
    }
}
