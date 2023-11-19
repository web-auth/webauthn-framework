<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\Exception\InvalidTrustPathException;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EcdaaKeyIdTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\TrustPath\TrustPath;
use function array_key_exists;

final class TrustPathDenormalizer implements DenormalizerInterface
{
    public function denormalize(mixed $data, string $type, string $format = null, array $context = []): mixed
    {
        return match (true) {
            array_key_exists('ecdaaKeyId', $data) => new EcdaaKeyIdTrustPath($data),
            array_key_exists('x5c', $data) => CertificateTrustPath::create($data),
            $data === [], isset($data['type']) && $data['type'] === EmptyTrustPath::class => EmptyTrustPath::create(),
            default => throw new InvalidTrustPathException('Unsupported trust path type'),
        };
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        return $type === TrustPath::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            TrustPath::class => true,
        ];
    }
}
