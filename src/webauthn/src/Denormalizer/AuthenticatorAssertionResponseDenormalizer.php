<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Exception\BadMethodCallException;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Util\Base64;

final class AuthenticatorAssertionResponseDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    private const ALREADY_CALLED = 'AUTHENTICATOR_ASSERTION_RESPONSE_PREPROCESS_ALREADY_CALLED';

    public function denormalize(mixed $data, string $type, string $format = null, array $context = [])
    {
        if ($this->denormalizer === null) {
            throw new BadMethodCallException('Please set a denormalizer before calling denormalize()!');
        }

        $data['authenticatorData'] = Base64::decode($data['authenticatorData']);
        $data['signature'] = Base64::decode($data['signature']);
        $data['clientDataJSON'] = Base64UrlSafe::decodeNoPadding($data['clientDataJSON']);
        $userHandle = $data['userHandle'] ?? null;
        if ($userHandle !== '' && $userHandle !== null) {
            $data['userHandle'] = Base64::decode($userHandle);
        }

        $context[self::ALREADY_CALLED] = true;
        return $this->denormalizer->denormalize($data, $type, $format, $context);
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        if ($context[self::ALREADY_CALLED] ?? false) {
            return false;
        }

        return $type === AuthenticatorAssertionResponse::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            AuthenticatorAssertionResponse::class => false,
        ];
    }
}
