<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use Assert\Assertion;
use function in_array;
use InvalidArgumentException;
use function Safe\class_implements;

abstract class TrustPathLoader
{
    /**
     * @param mixed[] $data
     */
    public static function loadTrustPath(array $data): TrustPath
    {
        Assertion::keyExists($data, 'type', 'The trust path type is missing');
        $type = $data['type'];
        if (class_exists($type) !== true) {
            throw new InvalidArgumentException(sprintf('The trust path type "%s" is not supported', $data['type']));
        }

        $implements = class_implements($type);
        if (in_array(TrustPath::class, $implements, true)) {
            return $type::createFromArray($data);
        }
        throw new InvalidArgumentException(sprintf('The trust path type "%s" is not supported', $data['type']));
    }
}
