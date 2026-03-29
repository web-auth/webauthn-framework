<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function assert;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\PublicKeyCredentialRpEntity;

final class PublicKeyCredentialRpEntityDenormalizer implements NormalizerInterface
{
    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            PublicKeyCredentialRpEntity::class => true,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function normalize(mixed $object, ?string $format = null, array $context = []): ?array
    {
        assert($object instanceof PublicKeyCredentialRpEntity);
        $data = array_filter(
            [
                'id' => $object->id,
                'name' => $object->name,
                'icon' => $object->icon,
            ],
            static fn (?string $value): bool => ($value !== null && $value !== ''),
        );

        return $data === [] ? null : $data;
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof PublicKeyCredentialRpEntity;
    }
}
