<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\TrustPath;
use Webauthn\Util\Base64;
use function array_key_exists;

final class PublicKeyCredentialSourceDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    public function denormalize(mixed $data, string $type, string $format = null, array $context = []): mixed
    {
        $keys = ['publicKeyCredentialId', 'credentialPublicKey', 'userHandle'];
        foreach ($keys as $key) {
            array_key_exists($key, $data) || throw InvalidDataException::create($data, 'Missing ' . $key);
            $data[$key] = Base64::decode($data[$key]);
        }

        return PublicKeyCredentialSource::create(
            $data['publicKeyCredentialId'],
            $data['type'],
            $data['transports'],
            $data['attestationType'],
            $this->denormalizer->denormalize($data['trustPath'], TrustPath::class, $format, $context),
            Uuid::fromString($data['aaguid']),
            $data['credentialPublicKey'],
            $data['userHandle'],
            $data['counter'],
            $data['otherUI'] ?? null,
            $data['backupEligible'] ?? null,
            $data['backupStatus'] ?? null,
            $data['uvInitialized'] ?? null,
        );
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        return $type === PublicKeyCredentialSource::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            PublicKeyCredentialSource::class => true,
        ];
    }
}
