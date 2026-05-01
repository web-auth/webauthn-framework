<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function array_key_exists;
use function array_map;
use function assert;
use function is_array;
use function is_string;
use function sprintf;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundPublicKey;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;
use Webauthn\SecurePaymentConfirmation\PaymentEntityLogo;

final class CollectedClientAdditionalPaymentDataDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface, NormalizerInterface, NormalizerAwareInterface
{
    use DenormalizerAwareTrait;
    use NormalizerAwareTrait;

    /**
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        if (! is_array($data)) {
            throw InvalidDataException::create(
                $data,
                'Invalid CollectedClientAdditionalPaymentData payload: expected an array.',
            );
        }

        // NOTE: For historical reasons, some implementations may use "rp" instead of "rpId".
        $rpId = $data['rpId'] ?? $data['rp'] ?? null;
        if (! is_string($rpId)) {
            throw InvalidDataException::create(
                $data,
                'Invalid CollectedClientAdditionalPaymentData payload: missing or invalid "rpId" field.',
            );
        }

        foreach (['topOrigin', 'total', 'instrument'] as $field) {
            if (! array_key_exists($field, $data)) {
                throw InvalidDataException::create(
                    $data,
                    sprintf('Invalid CollectedClientAdditionalPaymentData payload: missing "%s" field.', $field),
                );
            }
        }
        if (! is_string($data['topOrigin'])) {
            throw InvalidDataException::create(
                $data,
                'Invalid CollectedClientAdditionalPaymentData payload: "topOrigin" must be a string.',
            );
        }
        foreach (['payeeName', 'payeeOrigin'] as $optional) {
            if (array_key_exists($optional, $data) && ! is_string($data[$optional])) {
                throw InvalidDataException::create(
                    $data,
                    sprintf(
                        'Invalid CollectedClientAdditionalPaymentData payload: "%s" must be a string.',
                        $optional,
                    ),
                );
            }
        }
        if (array_key_exists('paymentEntitiesLogos', $data) && ! is_array($data['paymentEntitiesLogos'])) {
            throw InvalidDataException::create(
                $data,
                'Invalid CollectedClientAdditionalPaymentData payload: "paymentEntitiesLogos" must be an array.',
            );
        }

        $total = $this->denormalizer->denormalize($data['total'], PaymentCurrencyAmount::class, $format, $context);
        assert($total instanceof PaymentCurrencyAmount);

        $instrument = $this->denormalizer->denormalize(
            $data['instrument'],
            PaymentCredentialInstrument::class,
            $format,
            $context
        );
        assert($instrument instanceof PaymentCredentialInstrument);

        $logos = [];
        if (array_key_exists('paymentEntitiesLogos', $data)) {
            /** @var array<int, mixed> $logosData */
            $logosData = $data['paymentEntitiesLogos'];
            $logos = array_map(
                fn (mixed $logoData): PaymentEntityLogo => $this->denormalizeLogo($logoData, $format, $context),
                $logosData,
            );
        }

        $browserBoundPublicKey = null;
        // `browserBoundPublicKey` is only meaningful in a registration's
        // clientData.payment (per W3C SPC §5.1). In an assertion the user
        // agent may omit it entirely or send a stub object — only attempt
        // to denormalize when the required `publicKey` field is present.
        if (is_array($data['browserBoundPublicKey'] ?? null)
            && array_key_exists('publicKey', $data['browserBoundPublicKey'])
        ) {
            $browserBoundPublicKey = $this->denormalizer->denormalize(
                $data['browserBoundPublicKey'],
                BrowserBoundPublicKey::class,
                $format,
                $context,
            );
            assert($browserBoundPublicKey instanceof BrowserBoundPublicKey);
        }

        return new CollectedClientAdditionalPaymentData(
            rpId: $rpId,
            topOrigin: $data['topOrigin'],
            total: $total,
            instrument: $instrument,
            payeeName: $data['payeeName'] ?? '',
            payeeOrigin: $data['payeeOrigin'] ?? '',
            paymentEntitiesLogos: $logos,
            browserBoundPublicKey: $browserBoundPublicKey,
        );
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === CollectedClientAdditionalPaymentData::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            CollectedClientAdditionalPaymentData::class => true,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): array
    {
        assert($object instanceof CollectedClientAdditionalPaymentData);
        $result = [
            'rpId' => $object->rpId,
            'topOrigin' => $object->topOrigin,
            'total' => $this->normalizer->normalize($object->total, $format, $context),
            'instrument' => $this->normalizer->normalize($object->instrument, $format, $context),
            'payeeName' => $object->payeeName,
            'payeeOrigin' => $object->payeeOrigin,
        ];
        if ($object->paymentEntitiesLogos !== []) {
            $result['paymentEntitiesLogos'] = array_map(
                fn (PaymentEntityLogo $logo): mixed => $this->normalizer->normalize($logo, $format, $context),
                $object->paymentEntitiesLogos,
            );
        }
        if ($object->browserBoundPublicKey !== null) {
            $result['browserBoundPublicKey'] = $this->normalizer->normalize(
                $object->browserBoundPublicKey,
                $format,
                $context,
            );
        }

        return $result;
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof CollectedClientAdditionalPaymentData;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function denormalizeLogo(mixed $data, ?string $format, array $context): PaymentEntityLogo
    {
        $logo = $this->denormalizer->denormalize($data, PaymentEntityLogo::class, $format, $context);
        assert($logo instanceof PaymentEntityLogo);

        return $logo;
    }
}
