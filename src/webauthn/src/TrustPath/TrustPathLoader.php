<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use function array_key_exists;
use function class_implements;
use function in_array;
use InvalidArgumentException;

abstract class TrustPathLoader
{
    /**
     * @param mixed[] $data
     */
    public static function loadTrustPath(array $data): TrustPath
    {
        array_key_exists('type', $data) || throw new InvalidArgumentException('The trust path type is missing');
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
