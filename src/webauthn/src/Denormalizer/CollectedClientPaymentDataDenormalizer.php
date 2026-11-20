<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function array_diff;
use function array_key_exists;
use function array_keys;
use function assert;
use function is_array;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentRegistrationData;
use Webauthn\SecurePaymentConfirmation\CollectedClientPaymentData;

final class CollectedClientPaymentDataDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface, NormalizerInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;

    private const REGISTRATION_CLIENT_DATA_TYPE = 'webauthn.create';

    /**
     * The `payment` member is the registration dictionary when the client data type is `webauthn.create`, and the
     * authentication dictionary for any other type. The normalized form of this class carries no type: without one,
     * the member is the registration dictionary when `browserBoundPublicKey` is its only member, or when it is empty.
     *
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        if (! is_array($data)) {
            throw InvalidDataException::create(
                $data,
                'Invalid CollectedClientPaymentData payload: expected an array.',
            );
        }
        if (! array_key_exists('payment', $data)) {
            throw InvalidDataException::create(
                $data,
                'Invalid CollectedClientPaymentData payload: missing "payment" field.',
            );
        }

        $payment = $this->denormalizer->denormalize(
            $data['payment'],
            self::isRegistration($data) ? CollectedClientAdditionalPaymentRegistrationData::class : CollectedClientAdditionalPaymentData::class,
            $format,
            $context
        );

        return CollectedClientPaymentData::create($payment);
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === CollectedClientPaymentData::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            CollectedClientPaymentData::class => true,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): array
    {
        assert($object instanceof CollectedClientPaymentData);
        return [
            'payment' => $this->normalizer->normalize($object->payment, $format, $context),
        ];
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof CollectedClientPaymentData;
    }

    /**
     * @param array<array-key, mixed> $data
     */
    private static function isRegistration(array $data): bool
    {
        if (array_key_exists('type', $data)) {
            return $data['type'] === self::REGISTRATION_CLIENT_DATA_TYPE;
        }

        return is_array($data['payment']) && array_diff(array_keys($data['payment']), ['browserBoundPublicKey']) === [];
    }
}
