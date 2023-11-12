<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use Symfony\Component\Serializer\Exception\BadMethodCallException;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Util\Base64;
use function array_key_exists;

final class PublicKeyCredentialUserEntityDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    private const ALREADY_CALLED = 'PUBLIC_KEY_CREDENTIAL_USER_ENTITY_PREPROCESS_ALREADY_CALLED';

    public function denormalize(mixed $data, string $type, string $format = null, array $context = [])
    {
        if ($this->denormalizer === null) {
            throw new BadMethodCallException('Please set a denormalizer before calling denormalize()!');
        }
        if (! array_key_exists('id', $data)) {
            return $data;
        }
        $data['id'] = Base64::decode($data['id']);
        $context[self::ALREADY_CALLED] = true;

        return $this->denormalizer->denormalize($data, $type, $format, $context);
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        if ($context[self::ALREADY_CALLED] ?? false) {
            return false;
        }

        return $type === PublicKeyCredentialUserEntity::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            PublicKeyCredentialUserEntity::class => false,
        ];
    }
}
