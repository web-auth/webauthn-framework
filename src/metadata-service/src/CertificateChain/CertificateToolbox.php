<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\CertificateChain;

use function in_array;
use ParagonIE\ConstantTime\Base64;
use const PHP_EOL;
use function preg_replace;

class CertificateToolbox
{
    /**
     * @param string[] $data
     *
     * @return string[]
     */
    public static function fixPEMStructures(array $data, string $type = 'CERTIFICATE'): array
    {
        return array_map(static fn ($d): string => self::fixPEMStructure($d, $type), $data);
    }

    public static function fixPEMStructure(string $data, string $type = 'CERTIFICATE'): string
    {
        if (str_contains($data, '-----BEGIN')) {
            return trim($data);
        }
        $pem = '-----BEGIN ' . $type . '-----' . PHP_EOL;
        $pem .= chunk_split($data, 64, PHP_EOL);

        return $pem . ('-----END ' . $type . '-----' . PHP_EOL);
    }

    public static function convertPEMToDER(string $data): string
    {
        if (! str_contains($data, '-----BEGIN')) {
            return $data;
        }
        $data = preg_replace('/[\-]{5}.*[\-]{5}[\r\n]*/', '', $data);
        $data = preg_replace("/[\r\n]*/", '', $data);

        return Base64::decode(trim($data), true);
    }

    public static function convertDERToPEM(string $data, string $type = 'CERTIFICATE'): string
    {
        if (str_contains($data, '-----BEGIN')) {
            return $data;
        }
        $der = self::unusedBytesFix($data);

        return self::fixPEMStructure(base64_encode($der), $type);
    }

    /**
     * @param string[] $data
     *
     * @return string[]
     */
    public static function convertAllDERToPEM(iterable $data, string $type = 'CERTIFICATE'): array
    {
        $certificates = [];
        foreach ($data as $d) {
            $certificates[] = self::convertDERToPEM($d, $type);
        }

        return $certificates;
    }

    private static function unusedBytesFix(string $data): string
    {
        $hash = hash('sha256', $data);
        if (in_array($hash, self::getCertificateHashes(), true)) {
            $data[mb_strlen($data, '8bit') - 257] = "\0";
        }

        return $data;
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
