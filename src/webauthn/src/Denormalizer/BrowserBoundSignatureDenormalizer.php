<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function array_key_exists;
use function assert;
use function is_array;
use function is_string;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundSignature;

final class BrowserBoundSignatureDenormalizer implements DenormalizerInterface, NormalizerInterface
{
    /**
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        if (! is_array($data)) {
            throw InvalidDataException::create($data, 'Invalid BrowserBoundSignature payload: expected an array.');
        }
        if (! array_key_exists('signature', $data) || ! is_string($data['signature'])) {
            throw InvalidDataException::create(
                $data,
                'Invalid BrowserBoundSignature payload: missing or invalid "signature" field.',
            );
        }

        return new BrowserBoundSignature(signature: Base64UrlSafe::decodeNoPadding($data['signature']));
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === BrowserBoundSignature::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            BrowserBoundSignature::class => true,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): array
    {
        assert($object instanceof BrowserBoundSignature);
        return [
            'signature' => Base64UrlSafe::encodeUnpadded($object->signature),
        ];
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof BrowserBoundSignature;
    }
}
