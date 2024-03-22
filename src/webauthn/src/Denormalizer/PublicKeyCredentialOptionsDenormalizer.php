<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Exception\BadMethodCallException;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use function array_key_exists;
use function in_array;

final class PublicKeyCredentialOptionsDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    public function denormalize(mixed $data, string $type, string $format = null, array $context = []): mixed
    {
        if (array_key_exists('challenge', $data)) {
            $data['challenge'] = Base64UrlSafe::decodeNoPadding($data['challenge']);
        }

        foreach (['allowCredentials', 'excludeCredentials'] as $key) {
            if (array_key_exists($key, $data)) {
                foreach ($data[$key] ?? [] as $item => $allowCredential) {
                    $data[$key][$item]['id'] = Base64UrlSafe::decodeNoPadding($allowCredential['id']);
                }
            }
        }
        if ($type === PublicKeyCredentialCreationOptions::class) {
            return PublicKeyCredentialCreationOptions::create(
                $this->denormalizer->denormalize($data['rp'], PublicKeyCredentialRpEntity::class, $format, $context),
                $this->denormalizer->denormalize(
                    $data['user'],
                    PublicKeyCredentialUserEntity::class,
                    $format,
                    $context
                ),
                $data['challenge'],
                ! isset($data['pubKeyCredParams']) ? [] : $this->denormalizer->denormalize(
                    $data['pubKeyCredParams'],
                    PublicKeyCredentialParameters::class . '[]',
                    $format,
                    $context
                ),
                ! isset($data['authenticatorSelection']) ? null : $this->denormalizer->denormalize(
                    $data['authenticatorSelection'],
                    AuthenticatorSelectionCriteria::class,
                    $format,
                    $context
                ),
                $data['attestation'] ?? null,
                ! isset($data['excludeCredentials']) ? [] : $this->denormalizer->denormalize(
                    $data['excludeCredentials'],
                    PublicKeyCredentialDescriptor::class . '[]',
                    $format,
                    $context
                ),
                $data['timeout'] ?? null,
                ! isset($data['extensions']) ? null : $this->denormalizer->denormalize(
                    $data['extensions'],
                    AuthenticationExtensions::class,
                    $format,
                    $context
                ),
            );
        }
        if ($type === PublicKeyCredentialRequestOptions::class) {
            return PublicKeyCredentialRequestOptions::create(
                $data['challenge'],
                $data['rpId'] ?? null,
                ! isset($data['allowCredentials']) ? [] : $this->denormalizer->denormalize(
                    $data['allowCredentials'],
                    PublicKeyCredentialDescriptor::class . '[]',
                    $format,
                    $context
                ),
                $data['userVerification'] ?? null,
                $data['timeout'] ?? null,
                ! isset($data['extensions']) ? null : $this->denormalizer->denormalize(
                    $data['extensions'],
                    AuthenticationExtensions::class,
                    $format,
                    $context
                ),
            );
        }
        throw new BadMethodCallException('Unsupported type');
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
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
            PublicKeyCredentialCreationOptions::class => true,
            PublicKeyCredentialRequestOptions::class => true,
        ];
    }
}
