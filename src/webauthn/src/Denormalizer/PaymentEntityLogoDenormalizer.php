<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function array_key_exists;
use function assert;
use function is_array;
use function is_string;
use function sprintf;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\PaymentEntityLogo;

final class PaymentEntityLogoDenormalizer implements DenormalizerInterface, NormalizerInterface
{
    /**
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        if (! is_array($data)) {
            throw InvalidDataException::create($data, 'Invalid PaymentEntityLogo payload: expected an array.');
        }
        foreach (['url', 'label'] as $field) {
            if (! array_key_exists($field, $data) || ! is_string($data[$field])) {
                throw InvalidDataException::create(
                    $data,
                    sprintf('Invalid PaymentEntityLogo payload: missing or invalid "%s" field.', $field),
                );
            }
        }
        /** @var array{url: string, label: string} $data */

        return new PaymentEntityLogo(url: $data['url'], label: $data['label']);
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === PaymentEntityLogo::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            PaymentEntityLogo::class => true,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): array
    {
        assert($object instanceof PaymentEntityLogo);
        return [
            'url' => $object->url,
            'label' => $object->label,
        ];
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof PaymentEntityLogo;
    }
}
