<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Exception\BadMethodCallException;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use function array_key_exists;
use function in_array;

final class PublicKeyCredentialOptionsDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    private const ALREADY_CALLED = 'PUBLIC_KEY_CREDENTIAL_OPTIONS_PREPROCESS_ALREADY_CALLED';

    public function denormalize(mixed $data, string $type, string $format = null, array $context = [])
    {
        if ($this->denormalizer === null) {
            throw new BadMethodCallException('Please set a denormalizer before calling denormalize()!');
        }
        if (! array_key_exists('challenge', $data)) {
            return $data;
        }

        $data['challenge'] = Base64UrlSafe::decodeNoPadding($data['challenge']);
        foreach (['allowCredentials', 'excludeCredentials'] as $key) {
            if (array_key_exists('allowCredentials', $data)) {
                foreach ($data[$key] ?? [] as $item => $allowCredential) {
                    $data[$key][$item]['id'] = Base64UrlSafe::decodeNoPadding($allowCredential['id']);
                }
            }
        }
        $context[self::ALREADY_CALLED] = true;

        return $this->denormalizer->denormalize($data, $type, $format, $context);
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        if ($context[self::ALREADY_CALLED] ?? false) {
            return false;
        }

        return in_array(
            $type,
            [PublicKeyCredentialCreationOptions::class, PublicKeyCredentialRequestOptions::class],
            true
        );
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            PublicKeyCredentialCreationOptions::class => false,
            PublicKeyCredentialRequestOptions::class => false,
        ];
    }
}
