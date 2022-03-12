<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use function array_key_exists;
use Assert\Assertion;
use function in_array;
use InvalidArgumentException;
use JetBrains\PhpStorm\ArrayShape;
use function Safe\class_implements;
use function Safe\sprintf;

abstract class TrustPathLoader
{
    /**
     * @param mixed[] $data
     */
    public static function loadTrustPath(array $data): TrustPath
    {
        Assertion::keyExists($data, 'type', 'The trust path type is missing');
        $type = $data['type'];
        $oldTypes = self::oldTrustPathTypes();
        switch (true) {
            case array_key_exists($type, $oldTypes):
                return $oldTypes[$type]::createFromArray($data);
            case class_exists($type):
                $implements = class_implements($type);
                if (in_array(TrustPath::class, $implements, true)) {
                    return $type::createFromArray($data);
                }
                // no break
            default:
                throw new InvalidArgumentException(sprintf('The trust path type "%s" is not supported', $data['type']));
        }
    }

    
    #[ArrayShape(['empty' => 'string', 'ecdaa_key_id' => 'string', 'x5c' => 'string'])]
    private static function oldTrustPathTypes(): array
    {
        return [
            'empty' => EmptyTrustPath::class,
            'ecdaa_key_id' => EcdaaKeyIdTrustPath::class,
            'x5c' => CertificateTrustPath::class,
        ];
    }
}
