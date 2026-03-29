<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\JsonType;
use Webauthn\PublicKeyCredentialDescriptor;
use function assert;
use function is_string;

final class PublicKeyCredentialDescriptorType extends JsonType
{
    use SerializerTrait;

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if (! $value instanceof PublicKeyCredentialDescriptor) {
            assert($value === null || is_string($value));
            return $value;
        }

        return $this->serialize($value);
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?PublicKeyCredentialDescriptor
    {
        if ($value === null || $value instanceof PublicKeyCredentialDescriptor) {
            return $value;
        }

        /** @var string $value */
        return $this->deserialize($value, PublicKeyCredentialDescriptor::class);
    }

    public function getName(): string
    {
        return 'public_key_credential_descriptor';
    }
}
