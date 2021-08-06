<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use JetBrains\PhpStorm\Pure;
use function Safe\json_encode;
use Webauthn\PublicKeyCredentialDescriptor;

final class PublicKeyCredentialDescriptorType extends Type
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
    public function convertToPHPValue($value, AbstractPlatform $platform): ?PublicKeyCredentialDescriptor
    {
        if (null === $value || $value instanceof PublicKeyCredentialDescriptor) {
            return $value;
        }

        return PublicKeyCredentialDescriptor::createFromString($value);
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
    #[Pure]
    public function getName(): string
    {
        return 'public_key_credential_descriptor';
    }

    /**
     * {@inheritdoc}
     */
    #[Pure]
    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }
}
