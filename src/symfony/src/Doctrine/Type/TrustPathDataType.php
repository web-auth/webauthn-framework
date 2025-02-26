<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\JsonType;
use Doctrine\DBAL\Types\Type;
use Webauthn\TrustPath\TrustPath;

final class TrustPathDataType extends Type
{
    use SerializerTrait;

    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if (! $value instanceof TrustPath) {
            return $value;
        }

        return $this->serialize($value);
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?TrustPath
    {
        if ($value === null || $value instanceof TrustPath) {
            return $value;
        }

        return $this->deserialize($value, TrustPath::class);
    }

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($column);
    }

    public function getName(): string
    {
        return 'trust_path';
    }

    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        if (method_exists(JsonType::class, 'requiresSQLCommentHint')) {
            return (new JsonType())->requiresSQLCommentHint($platform);
        }

        return false;
    }
}
