<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use Assert\Assertion;
use InvalidArgumentException;
use function Safe\file_put_contents;
use function Safe\tempnam;
use function Safe\unlink;
use Symfony\Component\Process\Process;

class CertificateToolbox
{
    public static function checkChain(array $certificates): void
    {
        /*if (1 <= \count($certificates)) {
            return;
        }*/
        $tmpFiles = [];

        foreach ($certificates as $certificate) {
            $parsed = openssl_x509_parse($certificate);
            Assertion::isArray($parsed, 'Unable to read the certificate');
            Assertion::keyExists($parsed, 'validTo_time_t', 'The certificate has no validity period');
            Assertion::keyExists($parsed, 'validFrom_time_t', 'The certificate has no validity period');
            Assertion::lessOrEqualThan(time(), $parsed['validTo_time_t'], 'The certificate expired');
            Assertion::greaterOrEqualThan(time(), $parsed['validFrom_time_t'], 'The certificate is not usable yet');

            $filename = tempnam(sys_get_temp_dir(), 'webauthn-');
            file_put_contents($filename, $certificate);
            $tmpFiles[] = $filename;
        }
        $filenames = $tmpFiles;
        $endCertificate = array_shift($filenames);

        $processArguments = [
            '-check_ss_sig',
            '-partial_chain',
        ];
        if (\count($filenames) >= 1) {
            $processArguments[] = '-CAfile';
            $processArguments[] = array_pop($filenames);
        }

        while (0 !== \count($filenames)) {
            $processArguments[] = '-untrusted';
            $processArguments[] = array_pop($filenames);
        }
        $processArguments[] = $endCertificate;
        array_unshift($processArguments, 'openssl', 'verify');

        $process = new Process($processArguments);
        $process->start();
        while ($process->isRunning()) {
        }
        foreach ($filenames as $filename) {
            unlink($filename);
        }
        if (!$process->isSuccessful()) {
            throw new InvalidArgumentException('Invalid certificate or certificate chain. Error is: '.$process->getErrorOutput());
        }
    }

    public static function convertDERToPEM(string $certificate): string
    {
        $derCertificate = self::unusedBytesFix($certificate);
        $pemCert = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $pemCert .= chunk_split(base64_encode($derCertificate), 64, PHP_EOL);
        $pemCert .= '-----END CERTIFICATE-----'.PHP_EOL;

        return $pemCert;
    }

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
     * @return string[]
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
