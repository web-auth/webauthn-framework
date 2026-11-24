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
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorResponse;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\Util\Base64;

final class PublicKeyCredentialDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    /**
     * Context key under which the client extension results of the credential are handed to the denormalizers of the
     * authenticator responses, which attach them to the response they build.
     */
    public const CLIENT_EXTENSION_RESULTS = 'webauthn_client_extension_results';

    /**
     * @throws InvalidDataException
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        is_array($data) || throw InvalidDataException::create(
            $data,
            'Invalid public key credential. Shall be an object.'
        );
        /** @var array{id: string, rawId: string, type: string, response: array<string, mixed>, clientExtensionResults?: mixed} $data */
        $keys = ['id', 'rawId', 'type', 'response'];
        foreach ($keys as $key) {
            array_key_exists($key, $data) || throw InvalidDataException::create($data, 'Missing ' . $key);
        }
        foreach (['id', 'rawId', 'type'] as $key) {
            is_string($data[$key]) || throw InvalidDataException::create(
                $data,
                sprintf('Invalid parameter "%s". Shall be a string.', $key)
            );
        }
        is_array($data['response']) || throw InvalidDataException::create(
            $data,
            'Invalid parameter "response". Shall be an object.'
        );
        $data['type'] === PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY || throw InvalidDataException::create(
            $data,
            'Invalid parameter "type". Shall be "public-key".'
        );
        $id = Base64UrlSafe::decodeNoPadding($data['id']);
        $rawId = Base64::decode($data['rawId']);
        hash_equals($id, $rawId) || throw InvalidDataException::create($data, 'Invalid ID');
        $data['rawId'] = $rawId;

        $context[self::CLIENT_EXTENSION_RESULTS] = self::clientExtensionResults($data['clientExtensionResults'] ?? null);

        /** @var AuthenticatorResponse $response */
        $response = $this->denormalizer->denormalize(
            $data['response'],
            AuthenticatorResponse::class,
            $format,
            $context
        );

        return PublicKeyCredential::create($data['type'], $data['rawId'], $response);
    }

    /**
     * The client extension results are read leniently: a missing member, `null` or anything that is not a map of
     * extension identifiers gives `null`, as before they were read at all. The ceremony steps that need them, such as
     * the Secure Payment Confirmation one, refuse the response when they are missing while the signed data says they
     * should be there.
     */
    private static function clientExtensionResults(mixed $data): null|AuthenticationExtensions
    {
        if (! is_array($data)) {
            return null;
        }
        $extensions = [];
        foreach ($data as $name => $value) {
            if (! is_string($name)) {
                return null;
            }
            $extensions[] = AuthenticationExtension::create($name, $value);
        }

        return AuthenticationExtensions::create($extensions);
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === PublicKeyCredential::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            PublicKeyCredential::class => true,
        ];
    }
}
