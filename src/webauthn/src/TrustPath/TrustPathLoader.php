<?php

declare(strict_types=1);

namespace Webauthn\TrustPath;

use function array_key_exists;
use function class_implements;
use function in_array;
use Webauthn\Exception\InvalidTrustPathException;

abstract class TrustPathLoader
{
    /**
     * @param mixed[] $data
     */
    public static function loadTrustPath(array $data): TrustPath
    {
        array_key_exists('type', $data) || throw InvalidTrustPathException::create('The trust path type is missing');
        $type = $data['type'];
        if (class_exists($type) !== true) {
            throw InvalidTrustPathException::create(
                sprintf('The trust path type "%s" is not supported', $data['type'])
            );
        }

        $implements = class_implements($type);
        if (in_array(TrustPath::class, $implements, true)) {
            return $type::createFromArray($data);
        }
        throw InvalidTrustPathException::create(sprintf('The trust path type "%s" is not supported', $data['type']));
    }
}
