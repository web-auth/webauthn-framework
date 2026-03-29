<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\JsonType;
use Webauthn\TrustPath\TrustPath;
use function assert;
use function is_string;

final class TrustPathDataType extends JsonType
{
    use SerializerTrait;

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if (! $value instanceof TrustPath) {
            assert($value === null || is_string($value));
            return $value;
        }

        return $this->serialize($value);
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?TrustPath
    {
        if ($value === null || $value instanceof TrustPath) {
            return $value;
        }

        /** @var string $value */
        return $this->deserialize($value, TrustPath::class);
    }

    public function getName(): string
    {
        return 'trust_path';
    }
}
