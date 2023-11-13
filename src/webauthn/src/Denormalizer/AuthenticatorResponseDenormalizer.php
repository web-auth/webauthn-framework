<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use Symfony\Component\Serializer\Exception\BadMethodCallException;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorResponse;
use Webauthn\Exception\InvalidDataException;
use function array_key_exists;

final class AuthenticatorResponseDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    private const ALREADY_CALLED = 'AUTHENTICATOR_RESPONSE_PREPROCESS_ALREADY_CALLED';

    public function denormalize(mixed $data, string $type, string $format = null, array $context = [])
    {
        if ($this->denormalizer === null) {
            throw new BadMethodCallException('Please set a denormalizer before calling denormalize()!');
        }

        switch (true) {
            case ! array_key_exists('authenticatorData', $data) && ! array_key_exists('signature', $data):
                $context[self::ALREADY_CALLED] = true;
                return $this->denormalizer->denormalize(
                    $data,
                    AuthenticatorAttestationResponse::class,
                    $format,
                    $context
                );
            case array_key_exists('authenticatorData', $data) && array_key_exists('signature', $data):
                $context[self::ALREADY_CALLED] = true;
                return $this->denormalizer->denormalize(
                    $data,
                    AuthenticatorAssertionResponse::class,
                    $format,
                    $context
                );
            default:
                throw InvalidDataException::create($data, 'Unable to create the response object');
        }
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        if ($context[self::ALREADY_CALLED] ?? false) {
            return false;
        }

        return $type === AuthenticatorResponse::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            AuthenticatorResponse::class => false,
        ];
    }
}
