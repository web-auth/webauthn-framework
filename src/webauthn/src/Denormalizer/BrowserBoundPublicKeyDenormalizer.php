<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function array_key_exists;
use function assert;
use function is_array;
use function is_int;
use function is_string;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundPublicKey;

final class BrowserBoundPublicKeyDenormalizer implements DenormalizerInterface, NormalizerInterface
{
    /**
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        if (! is_array($data)) {
            throw InvalidDataException::create($data, 'Invalid BrowserBoundPublicKey payload: expected an array.');
        }
        if (! array_key_exists('publicKey', $data) || ! is_string($data['publicKey'])) {
            throw InvalidDataException::create(
                $data,
                'Invalid BrowserBoundPublicKey payload: missing or invalid "publicKey" field.',
            );
        }
        if (! array_key_exists('algorithm', $data) || ! is_int($data['algorithm'])) {
            throw InvalidDataException::create(
                $data,
                'Invalid BrowserBoundPublicKey payload: missing or invalid "algorithm" field.',
            );
        }

        return new BrowserBoundPublicKey(
            publicKey: Base64UrlSafe::decodeNoPadding($data['publicKey']),
            algorithm: $data['algorithm'],
        );
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

    /**
     * @return array<string, mixed>
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): array
    {
        assert($object instanceof BrowserBoundPublicKey);
        return [
            'publicKey' => Base64UrlSafe::encodeUnpadded($object->publicKey),
            'algorithm' => $object->algorithm,
        ];
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof BrowserBoundPublicKey;
    }
}
