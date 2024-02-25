<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Webauthn\TrustPath\TrustPath;
use Webauthn\TrustPath\TrustPathLoader;
use function is_array;
use function is_string;
use const JSON_THROW_ON_ERROR;

final class TrustPathDataType extends Type
{
    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if ($value === null || is_string($value)) {
            return $value;
        }
        if ($value instanceof TrustPath) {
            return json_encode($value, JSON_THROW_ON_ERROR);
        }

        return null;
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?TrustPath
    {
        if ($value === null || $value instanceof TrustPath) {
            return $value;
        }
        if (! is_string($value)) {
            return null;
        }
        $json = json_decode($value, true, flags: JSON_THROW_ON_ERROR);
        if (! is_array($json)) {
            return null;
        }

        return TrustPathLoader::loadTrustPath($json);
    }

    public function getSQLDeclaration(array $fieldDeclaration, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($fieldDeclaration);
    }

    public function getName(): string
    {
        return 'trust_path';
    }

    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }
}
