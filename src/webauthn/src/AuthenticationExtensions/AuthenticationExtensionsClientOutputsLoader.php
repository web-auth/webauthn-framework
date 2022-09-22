<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use CBOR\CBORObject;
use CBOR\MapObject;
use InvalidArgumentException;
use function is_string;

abstract class AuthenticationExtensionsClientOutputsLoader
{
    public static function load(CBORObject $object): AuthenticationExtensionsClientOutputs
    {
        $object instanceof MapObject || throw new InvalidArgumentException('Invalid extension object');
        $data = $object->normalize();
        $extensions = AuthenticationExtensionsClientOutputs::create();
        foreach ($data as $key => $value) {
            is_string($key) || throw new InvalidArgumentException('Invalid extension key');
            $extensions->add(AuthenticationExtension::create($key, $value));
        }

        return $extensions;
    }
}
