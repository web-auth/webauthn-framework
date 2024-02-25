<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Webauthn\PublicKeyCredentialDescriptor;
use function is_string;
use const JSON_THROW_ON_ERROR;

final class PublicKeyCredentialDescriptorType extends Type
{
    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if (is_string($value)) {
            return $value;
        }
        if ($value === null) {
            return $value;
        }

        return json_encode($value, JSON_THROW_ON_ERROR);
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?PublicKeyCredentialDescriptor
    {
        if ($value === null || $value instanceof PublicKeyCredentialDescriptor) {
            return $value;
        }
        if (! is_string($value)) {
            return null;
        }

        return PublicKeyCredentialDescriptor::createFromString($value);
    }

    public function getSQLDeclaration(array $fieldDeclaration, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($fieldDeclaration);
    }

    public function getName(): string
    {
        return 'public_key_credential_descriptor';
    }

    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }
}
