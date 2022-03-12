<?php

declare(strict_types=1);

namespace Webauthn\Util;

use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\ECDSA\ECSignature;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\Signature;

/**
 * This class fixes the signature of the ECDSA based algorithms.
 *
 * @internal
 *
 * @see https://www.w3.org/TR/webauthn/#signature-attestation-types
 */
abstract class CoseSignatureFixer
{
    public static function fix(string $signature, Signature $algorithm): string
    {
        switch ($algorithm::identifier()) {
            case ES256K::ID:
            case ES256::ID:
                if (mb_strlen($signature, '8bit') === 64) {
                    return $signature;
                }

                return ECSignature::fromAsn1(
                    $signature,
                    64
                ); //TODO: fix this hardcoded value by adding a dedicated method for the algorithms
            case ES384::ID:
                if (mb_strlen($signature, '8bit') === 96) {
                    return $signature;
                }

                return ECSignature::fromAsn1($signature, 96);
            case ES512::ID:
                if (mb_strlen($signature, '8bit') === 132) {
                    return $signature;
                }

                return ECSignature::fromAsn1($signature, 132);
        }

        return $signature;
    }
}
