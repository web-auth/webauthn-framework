<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Exception\BadMethodCallException;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Util\Base64;

final class AuthenticatorAttestationResponseDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    private const ALREADY_CALLED = 'AUTHENTICATOR_ATTESTATIONN_RESPONSE_PREPROCESS_ALREADY_CALLED';

    public function denormalize(mixed $data, string $type, string $format = null, array $context = [])
    {
        if ($this->denormalizer === null) {
            throw new BadMethodCallException('Please set a denormalizer before calling denormalize()!');
        }

        $data['clientDataJSON'] = Base64UrlSafe::decodeNoPadding($data['clientDataJSON']);
        $data['attestationObject'] = Base64::decode($data['attestationObject']);

        $context[self::ALREADY_CALLED] = true;

        return $this->denormalizer->denormalize($data, $type, $format, $context);
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        if ($context[self::ALREADY_CALLED] ?? false) {
            return false;
        }

        return $type === AuthenticatorAttestationResponse::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            AuthenticatorAttestationResponse::class => false,
        ];
    }
}
