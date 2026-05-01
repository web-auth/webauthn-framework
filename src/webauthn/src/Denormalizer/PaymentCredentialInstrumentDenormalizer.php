<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function array_key_exists;
use function assert;
use function is_array;
use function is_bool;
use function is_string;
use function sprintf;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;

final class PaymentCredentialInstrumentDenormalizer implements DenormalizerInterface, NormalizerInterface
{
    /**
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        if (! is_array($data)) {
            throw InvalidDataException::create(
                $data,
                'Invalid PaymentCredentialInstrument payload: expected an array.',
            );
        }
        foreach (['displayName', 'icon'] as $field) {
            if (! array_key_exists($field, $data) || ! is_string($data[$field])) {
                throw InvalidDataException::create(
                    $data,
                    sprintf('Invalid PaymentCredentialInstrument payload: missing or invalid "%s" field.', $field),
                );
            }
        }
        if (array_key_exists('iconMustBeShown', $data) && ! is_bool($data['iconMustBeShown'])) {
            throw InvalidDataException::create(
                $data,
                'Invalid PaymentCredentialInstrument payload: "iconMustBeShown" must be a boolean.',
            );
        }
        if (array_key_exists('details', $data) && $data['details'] !== null && ! is_string($data['details'])) {
            throw InvalidDataException::create(
                $data,
                'Invalid PaymentCredentialInstrument payload: "details" must be a string or null.',
            );
        }
        /** @var array{displayName: string, icon: string, iconMustBeShown?: bool, details?: string|null} $data */

        return new PaymentCredentialInstrument(
            displayName: $data['displayName'],
            icon: $data['icon'],
            iconMustBeShown: $data['iconMustBeShown'] ?? true,
            details: $data['details'] ?? null,
        );
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === PaymentCredentialInstrument::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            PaymentCredentialInstrument::class => true,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): array
    {
        assert($object instanceof PaymentCredentialInstrument);
        $result = [
            'displayName' => $object->displayName,
            'icon' => $object->icon,
            'iconMustBeShown' => $object->iconMustBeShown,
        ];
        if ($object->details !== null) {
            $result['details'] = $object->details;
        }

        return $result;
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof PaymentCredentialInstrument;
    }
}
