<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function assert;
use function is_array;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundPublicKey;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentRegistrationData;

final class CollectedClientAdditionalPaymentRegistrationDataDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface, NormalizerInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;

    /**
     * The `browserBoundPublicKey` member is optional: the user agent omits it when it has no browser-bound key. When
     * present, it must be the base64url encoding of a COSE_Key, see {@see BrowserBoundPublicKeyDenormalizer}. Other
     * members are ignored, as a dictionary conversion does.
     *
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        is_array($data) || throw InvalidDataException::create(
            $data,
            'Invalid CollectedClientAdditionalPaymentRegistrationData payload: expected an array.',
        );

        $browserBoundPublicKey = null;
        if (isset($data['browserBoundPublicKey'])) {
            $browserBoundPublicKey = $this->denormalizer->denormalize(
                $data['browserBoundPublicKey'],
                BrowserBoundPublicKey::class,
                $format,
                $context,
            );
        }

        return CollectedClientAdditionalPaymentRegistrationData::create($browserBoundPublicKey);
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === CollectedClientAdditionalPaymentRegistrationData::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            CollectedClientAdditionalPaymentRegistrationData::class => true,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): array
    {
        assert($object instanceof CollectedClientAdditionalPaymentRegistrationData);
        if ($object->browserBoundPublicKey === null) {
            return [];
        }

        return [
            'browserBoundPublicKey' => $this->normalizer->normalize($object->browserBoundPublicKey, $format, $context),
        ];
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof CollectedClientAdditionalPaymentRegistrationData;
    }
}
