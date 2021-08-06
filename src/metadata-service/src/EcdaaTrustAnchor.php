<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use Base64Url\Base64Url;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use function Safe\sprintf;

class EcdaaTrustAnchor implements JsonSerializable
{
    #[Pure]
    public function __construct(private string $X, private string $Y, private string $c, private string $sx, private string $sy, private string $G1Curve)
    {
    }

    #[Pure]
    public function getX(): string
    {
        return $this->X;
    }

    #[Pure]
    public function getY(): string
    {
        return $this->Y;
    }

    #[Pure]
    public function getC(): string
    {
        return $this->c;
    }

    #[Pure]
    public function getSx(): string
    {
        return $this->sx;
    }

    #[Pure]
    public function getSy(): string
    {
        return $this->sy;
    }

    #[Pure]
    public function getG1Curve(): string
    {
        return $this->G1Curve;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        foreach (['X', 'Y', 'c', 'sx', 'sy', 'G1Curve'] as $key) {
            Assertion::keyExists($data, $key, sprintf('Invalid data. The key "%s" is missing', $key));
        }

        return new self(
            Base64Url::decode($data['X']),
            Base64Url::decode($data['Y']),
            Base64Url::decode($data['c']),
            Base64Url::decode($data['sx']),
            Base64Url::decode($data['sy']),
            $data['G1Curve']
        );
    }

    #[Pure]
    public function jsonSerialize(): array
    {
        $data = [
            'X' => Base64Url::encode($this->X),
            'Y' => Base64Url::encode($this->Y),
            'c' => Base64Url::encode($this->c),
            'sx' => Base64Url::encode($this->sx),
            'sy' => Base64Url::encode($this->sy),
            'G1Curve' => $this->G1Curve,
        ];

        return Utils::filterNullValues($data);
    }
}
