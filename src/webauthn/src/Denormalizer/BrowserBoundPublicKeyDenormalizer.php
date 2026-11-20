<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function assert;
use function is_string;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundPublicKey;
use Webauthn\Util\Base64;

/**
 * Reads and writes the browser-bound public key in the shape of W3C Secure Payment Confirmation: the base64url
 * encoding of a COSE_Key.
 */
final class BrowserBoundPublicKeyDenormalizer implements DenormalizerInterface, NormalizerInterface
{
    /**
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        is_string($data) || throw InvalidDataException::create(
            $data,
            'Invalid browserBoundPublicKey: expected the base64url encoding of a COSE_Key.'
        );

        return BrowserBoundPublicKey::create(Base64::decode($data));
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === BrowserBoundPublicKey::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            BrowserBoundPublicKey::class => true,
        ];
    }

    public function normalize(mixed $object, ?string $format = null, array $context = []): string
    {
        assert($object instanceof BrowserBoundPublicKey);

        return Base64UrlSafe::encodeUnpadded($object->publicKey);
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof BrowserBoundPublicKey;
    }
}
