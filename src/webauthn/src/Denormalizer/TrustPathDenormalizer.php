<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\Exception\InvalidTrustPathException;
use Webauthn\TrustPath\TrustPath;
use function array_key_exists;
use function in_array;

final class TrustPathDenormalizer implements DenormalizerInterface
{
    public function denormalize(mixed $data, string $type, string $format = null, array $context = [])
    {
        array_key_exists('type', $data) || throw InvalidTrustPathException::create('The trust path type is missing');
        $className = $data['type'];
        if (class_exists($className) !== true) {
            throw InvalidTrustPathException::create(
                sprintf('The trust path type "%s" is not supported', $data['type'])
            );
        }

        $implements = class_implements($className);
        if (! in_array(TrustPath::class, $implements, true)) {
            throw InvalidTrustPathException::create(
                sprintf('The trust path type "%s" is not supported', $data['type'])
            );
        }

        return $className::createFromArray($data);
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
