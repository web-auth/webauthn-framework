<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function array_key_exists;
use function is_array;
use function is_string;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function sprintf;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CollectedClientData;
use Webauthn\Exception\InvalidDataException;
use Webauthn\Util\Base64;

final class AuthenticatorAssertionResponseDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    /**
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        is_array($data) || throw InvalidDataException::create(
            $data,
            'Invalid authenticator assertion response. Shall be an object.'
        );
        /** @var array{authenticatorData: string, signature: string, clientDataJSON: string, userHandle?: ?string, attestationObject?: string} $data */
        $keys = ['authenticatorData', 'signature', 'clientDataJSON'];
        foreach ($keys as $key) {
            array_key_exists($key, $data) || throw InvalidDataException::create($data, 'Missing ' . $key);
            is_string($data[$key]) || throw InvalidDataException::create(
                $data,
                sprintf('Invalid parameter "%s". Shall be a string.', $key)
            );
        }
        $data['authenticatorData'] = Base64::decode($data['authenticatorData']);
        $data['signature'] = Base64::decode($data['signature']);
        $data['clientDataJSON'] = Base64UrlSafe::decodeNoPadding($data['clientDataJSON']);
        $userHandle = $data['userHandle'] ?? null;
        if ($userHandle !== '' && $userHandle !== null) {
            $userHandle = Base64::decode($userHandle);
        }

        /** @var CollectedClientData $clientDataJSON */
        $clientDataJSON = $this->denormalizer->denormalize(
            $data['clientDataJSON'],
            CollectedClientData::class,
            $format,
            $context
        );
        /** @var AuthenticatorData $authenticatorData */
        $authenticatorData = $this->denormalizer->denormalize(
            $data['authenticatorData'],
            AuthenticatorData::class,
            $format,
            $context
        );

        return AuthenticatorAssertionResponse::create(
            $clientDataJSON,
            $authenticatorData,
            $data['signature'],
            $userHandle ?? null,
            ! isset($data['attestationObject']) ? null : $this->denormalizer->denormalize(
                $data['attestationObject'],
                AttestationObject::class,
                $format,
                $context
            ),
        );
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === AuthenticatorAssertionResponse::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            AuthenticatorAssertionResponse::class => true,
        ];
    }
}
