<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use Assert\Assertion;

class CertificateToolbox
{
    public static function checkChain(array $x5c): void
    {
        Assertion::notEmpty($x5c, 'The attestation statement value "x5c" must be a list with at least one certificate.');
        reset($x5c);
        $currentCert = current($x5c);
        if (1 === \count($x5c)) {
            return;
        }

        $currentCertParsed = openssl_x509_parse($currentCert);
        while ($cert = next($x5c)) {
            $currentCertIssuer = \Safe\json_encode($currentCertParsed['issuer']);

            $nextCertParsed = openssl_x509_parse($cert);
            $nextCertAsPemSubject = \Safe\json_encode($nextCertParsed['subject']);

            Assertion::eq($currentCertIssuer, $nextCertAsPemSubject, 'Invalid certificate chain.');

            Assertion::keyExists($nextCertParsed, 'extensions', 'Invalid certificate chain.');
            Assertion::keyExists($nextCertParsed['extensions'], 'basicConstraints', 'Invalid certificate chain.');
            Assertion::startsWith($nextCertParsed['extensions']['basicConstraints'], 'CA:TRUE', 'Invalid certificate chain.');
            $currentCertParsed = $nextCertParsed;
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
