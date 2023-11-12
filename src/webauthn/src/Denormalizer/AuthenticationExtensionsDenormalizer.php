<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use Symfony\Component\Serializer\Exception\BadMethodCallException;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use function in_array;
use function is_string;

final class AuthenticationExtensionsDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    private const ALREADY_CALLED = 'AUTHENTICATION_EXTENSIONS_PREPROCESS_ALREADY_CALLED';

    public function denormalize(mixed $data, string $type, string $format = null, array $context = [])
    {
        if ($this->denormalizer === null) {
            throw new BadMethodCallException('Please set a denormalizer before calling denormalize()!');
        }
        foreach ($data as $key => $value) {
            if (! is_string($key)) {
                continue;
            }
            $data[$key] = AuthenticationExtension::create($key, $value);
        }

        $context[self::ALREADY_CALLED] = true;

        return $this->denormalizer->denormalize([
            'extensions' => $data,
        ], $type, $format, $context);
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        if ($context[self::ALREADY_CALLED] ?? false) {
            return false;
        }

        return in_array(
            $type,
            [
                AuthenticationExtensions::class,
                AuthenticationExtensionsClientOutputs::class,
                AuthenticationExtensionsClientInputs::class,
            ],
            true
        );
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            AuthenticationExtensions::class => false,
            AuthenticationExtensionsClientInputs::class => false,
            AuthenticationExtensionsClientOutputs::class => false,
        ];
    }
}
