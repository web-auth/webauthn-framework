<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function array_key_exists;
use JsonSerializable;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;

/**
 * @deprecated since 4.2.0 and will be removed in 5.0.0. The ECDAA Trust Anchor does no longer exist in Webauthn specification.
 * @final
 */
class EcdaaTrustAnchor implements JsonSerializable
{
    public function __construct(
        private readonly string $X,
        private readonly string $Y,
        private readonly string $c,
        private readonly string $sx,
        private readonly string $sy,
        private readonly string $G1Curve
    ) {
    }

    public function getX(): string
    {
        return $this->X;
    }

    public function getY(): string
    {
        return $this->Y;
    }

    public function getC(): string
    {
        return $this->c;
    }

    public function getSx(): string
    {
        return $this->sx;
    }

    public function getSy(): string
    {
        return $this->sy;
    }

    public function getG1Curve(): string
    {
        return $this->G1Curve;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        foreach (['X', 'Y', 'c', 'sx', 'sy', 'G1Curve'] as $key) {
            array_key_exists($key, $data) || throw MetadataStatementLoadingException::create(sprintf(
                'Invalid data. The key "%s" is missing',
                $key
            ));
        }

        return new self(
            Base64UrlSafe::decode($data['X']),
            Base64UrlSafe::decode($data['Y']),
            Base64UrlSafe::decode($data['c']),
            Base64UrlSafe::decode($data['sx']),
            Base64UrlSafe::decode($data['sy']),
            $data['G1Curve']
        );
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'X' => Base64UrlSafe::encodeUnpadded($this->X),
            'Y' => Base64UrlSafe::encodeUnpadded($this->Y),
            'c' => Base64UrlSafe::encodeUnpadded($this->c),
            'sx' => Base64UrlSafe::encodeUnpadded($this->sx),
            'sy' => Base64UrlSafe::encodeUnpadded($this->sy),
            'G1Curve' => $this->G1Curve,
        ];

        return Utils::filterNullValues($data);
    }
}
