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
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;

final class PaymentCurrencyAmountDenormalizer implements DenormalizerInterface, NormalizerInterface
{
    /**
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        if (! is_array($data)) {
            throw InvalidDataException::create($data, 'Invalid PaymentCurrencyAmount payload: expected an array.');
        }
        foreach (['currency', 'value'] as $field) {
            if (! array_key_exists($field, $data) || ! is_string($data[$field])) {
                throw InvalidDataException::create(
                    $data,
                    sprintf('Invalid PaymentCurrencyAmount payload: missing or invalid "%s" field.', $field),
                );
            }
        }
        /** @var array{currency: string, value: string} $data */

        return new PaymentCurrencyAmount(currency: $data['currency'], value: $data['value']);
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === PaymentCurrencyAmount::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            PaymentCurrencyAmount::class => true,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): array
    {
        assert($object instanceof PaymentCurrencyAmount);
        return [
            'currency' => $object->currency,
            'value' => $object->value,
        ];
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof PaymentCurrencyAmount;
    }
}
