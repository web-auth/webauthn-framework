<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use function assert;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\MetadataService\Statement\VerificationMethodANDCombinations;
use Webauthn\MetadataService\Statement\VerificationMethodDescriptor;

final class VerificationMethodANDCombinationsDenormalizer implements NormalizerInterface, NormalizerAwareInterface
{
    use NormalizerAwareTrait;

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            VerificationMethodANDCombinations::class => true,
        ];
    }

    /**
     * @return array<VerificationMethodDescriptor>
     */
    public function normalize(mixed $data, ?string $format = null, array $context = []): array
    {
        assert($data instanceof VerificationMethodANDCombinations);

        return array_map(
            fn ($verificationMethod) => $this->normalizer->normalize($verificationMethod, $format, $context),
            $data->verificationMethods
        );
    }

    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof VerificationMethodANDCombinations;
    }
}
