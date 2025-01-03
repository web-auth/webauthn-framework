<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\MetadataService\Statement\ExtensionDescriptor;
use function array_key_exists;

final class ExtensionDescriptorDenormalizer implements DenormalizerInterface
{
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        if (array_key_exists('fail_if_unknown', $data)) {
            $data['failIfUnknown'] = $data['fail_if_unknown'];
            unset($data['fail_if_unknown']);
        }

        return ExtensionDescriptor::create(...$data);
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === ExtensionDescriptor::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            ExtensionDescriptor::class => true,
        ];
    }
}
