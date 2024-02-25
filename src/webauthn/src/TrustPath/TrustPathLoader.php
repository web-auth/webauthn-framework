<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use Webauthn\Exception\InvalidTrustPathException;
use function array_key_exists;
use function is_array;

final class TrustPathLoader
{
    /**
     * @param mixed[] $data
     */
    public static function loadTrustPath(array $data): TrustPath
    {
        return match (true) {
            array_key_exists('x5c', $data) && is_array($data['x5c']) => CertificateTrustPath::create($data['x5c']),
            $data === [] => EmptyTrustPath::create(),
            default => throw new InvalidTrustPathException('Invalid trust path'),
        };
    }
}
