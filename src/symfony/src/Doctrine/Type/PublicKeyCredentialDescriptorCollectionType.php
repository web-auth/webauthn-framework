<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use function Safe\json_encode;
use Webauthn\PublicKeyCredentialDescriptorCollection;

final class PublicKeyCredentialDescriptorCollectionType extends Type
{
    /**
     * {@inheritdoc}
     */
    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if (null === $value) {
            return $value;
        }

        return json_encode($value);
    }

    /**
     * {@inheritdoc}
     */
    public function convertToPHPValue($value, AbstractPlatform $platform): ?PublicKeyCredentialDescriptorCollection
    {
        if (null === $value || $value instanceof PublicKeyCredentialDescriptorCollection) {
            return $value;
        }

        return PublicKeyCredentialDescriptorCollection::createFromString($value);
    }

    /**
     * {@inheritdoc}
     */
    public function getSQLDeclaration(array $fieldDeclaration, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($fieldDeclaration);
    }

    /**
     * {@inheritdoc}
     */
    
    public function getName(): string
    {
        return 'public_key_credential_descriptor_collection';
    }

    /**
     * {@inheritdoc}
     */
    
    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }
}
