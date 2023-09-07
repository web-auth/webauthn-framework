<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use InvalidArgumentException;
use function is_string;
use const JSON_THROW_ON_ERROR;

final class PublicKeyCredentialDescriptorCollectionType extends Type
{
    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return $value;
        }

        return json_encode($value, JSON_THROW_ON_ERROR);
    }

    public function convertToPHPValue(
        $value,
        AbstractPlatform $platform
    ): ?PublicKeyCredentialDescriptorCollection {
        if ($value === null || $value instanceof PublicKeyCredentialDescriptorCollection) {
            return $value;
        }
        is_string($value) || throw new InvalidArgumentException(sprintf(
            'Invalid type. Expected "%s", got "%s" instead.',
            'string',
            get_debug_type($value)
        ));

        return PublicKeyCredentialDescriptorCollection::createFromString($value);
    }

    public function getSQLDeclaration(array $fieldDeclaration, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($fieldDeclaration);
    }

    public function getName(): string
    {
        return 'public_key_credential_descriptor_collection';
    }

    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }
}
