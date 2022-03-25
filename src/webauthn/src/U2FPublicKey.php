<?php

declare(strict_types=1);

namespace Webauthn;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithms;
use Cose\Key\Ec2Key;

class U2FPublicKey
{
    public static function isU2FKey(string $publicKey): bool
    {
        return $publicKey[0] === "\x04" && mb_strlen($publicKey, '8bit') === 65;
    }

    public static function convertToCoseKey(string $publicKey): string
    {
        return MapObject::create([
            MapItem::create(
                UnsignedIntegerObject::create(Ec2Key::TYPE),
                UnsignedIntegerObject::create(Ec2Key::TYPE_EC2)
            ),
            MapItem::create(
                UnsignedIntegerObject::create(Ec2Key::ALG),
                NegativeIntegerObject::create(Algorithms::COSE_ALGORITHM_ES256)
            ),
            MapItem::create(
                NegativeIntegerObject::create(Ec2Key::DATA_CURVE),
                UnsignedIntegerObject::create(Ec2Key::CURVE_P256)
            ),
            MapItem::create(
                NegativeIntegerObject::create(Ec2Key::DATA_X),
                ByteStringObject::create(mb_substr($publicKey, 1, 32, '8bit'))
            ),
            MapItem::create(
                NegativeIntegerObject::create(Ec2Key::DATA_Y),
                ByteStringObject::create(mb_substr($publicKey, 33, null, '8bit'))
            ),
        ])->__toString();
    }
}
