<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Webauthn\TrustPath\TrustPath;
use Webauthn\TrustPath\TrustPathLoader;
use const JSON_THROW_ON_ERROR;

final class TrustPathDataType extends Type
{
    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return $value;
        }

        return json_encode($value, JSON_THROW_ON_ERROR);
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?TrustPath
    {
        if ($value === null || $value instanceof TrustPath) {
            return $value;
        }
        $json = json_decode((string) $value, true, flags: JSON_THROW_ON_ERROR);

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
