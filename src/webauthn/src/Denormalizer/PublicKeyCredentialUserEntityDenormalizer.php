<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Util\Base64;
use function array_key_exists;

final class PublicKeyCredentialUserEntityDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    public function denormalize(mixed $data, string $type, string $format = null, array $context = []): mixed
    {
        if (! array_key_exists('id', $data)) {
            return $data;
        }
        $data['id'] = Base64::decode($data['id']);

        return PublicKeyCredentialUserEntity::create(
            $data['name'],
            $data['id'],
            $data['displayName'],
            $data['icon'] ?? null
        );
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        return $type === PublicKeyCredentialUserEntity::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            PublicKeyCredentialUserEntity::class => true,
        ];
    }
}
