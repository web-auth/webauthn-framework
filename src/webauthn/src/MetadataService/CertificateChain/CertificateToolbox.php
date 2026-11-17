<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\CertificateChain;

use const PHP_EOL;

final readonly class CertificateToolbox
{
    private const PEM_HEADER = '-----BEGIN ';

    private const PEM_FOOTER = '-----END ';

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
        if (str_contains($data, self::PEM_HEADER)) {
            return trim($data);
        }
        $pem = self::PEM_HEADER . $type . '-----' . PHP_EOL;
        $pem .= chunk_split($data, 64, PHP_EOL);

        return $pem . (self::PEM_FOOTER . $type . '-----' . PHP_EOL);
    }

    /**
     * Encodes DER data, such as an entry of the "x5c" member of an attestation statement, as a single PEM block.
     *
     * The input is always treated as DER, even when it already looks like PEM text. Returning such text as is would let
     * the client that sent it choose what the PEM parser and the OpenSSL functions read: several PEM blocks that the two
     * readers resolve to different certificates, or a "file://" path that OpenSSL opens.
     */
    public static function convertDERToPEM(string $data, string $type = 'CERTIFICATE'): string
    {
        return self::fixPEMStructure(base64_encode($data), $type);
    }

    /**
     * @param string[] $data
     *
     * @return string[]
     */
    public static function convertAllDERToPEM(array $data, string $type = 'CERTIFICATE'): array
    {
        return array_map(static fn ($d): string => self::convertDERToPEM($d, $type), $data);
    }
}
