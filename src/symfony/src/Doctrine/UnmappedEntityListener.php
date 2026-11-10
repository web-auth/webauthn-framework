<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine;

use function array_keys;
use Doctrine\ORM\Event\LoadClassMetadataEventArgs;
use function is_subclass_of;
use LogicException;
use function sprintf;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Refuses the entities that still expect the Doctrine mapping removed in 6.0.0.
 *
 * Up to 5.4, an entity extending `Webauthn\CredentialRecord`, `Webauthn\PublicKeyCredentialUserEntity` or
 * `Webauthn\PublicKeyCredentialEntity` got its columns from the mapping provided by the bundle. Without it, Doctrine
 * only knows the properties declared by the entity itself, and a schema update would drop the columns holding the
 * credential records or the users. Such an entity is refused when its metadata is loaded, before any schema or query
 * uses it.
 *
 * An entity mapping the inherited properties itself, for instance through an XML mapping of the parent class, is
 * accepted. For a credential record, the property identifying the record is enough to tell it apart. For a user
 * entity, both properties the bundle used to map are required, as an application may have mapped one of them only.
 *
 * The parent classes are listed from the most specific one, so that the message names the class the entity actually
 * extends, which is also the class the application converts its entity from and to.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1007
 * @internal
 */
final class UnmappedEntityListener
{
    private const MAPPED_PROPERTIES = [
        CredentialRecord::class => ['publicKeyCredentialId'],
        PublicKeyCredentialUserEntity::class => ['name', 'displayName'],
        PublicKeyCredentialEntity::class => ['name'],
    ];

    public function loadClassMetadata(LoadClassMetadataEventArgs $event): void
    {
        $metadata = $event->getClassMetadata();
        if ($metadata->isMappedSuperclass) {
            return;
        }
        $className = $metadata->getName();
        $parentClass = $this->findParentClass($className);
        if ($parentClass === null) {
            return;
        }
        foreach (self::MAPPED_PROPERTIES[$parentClass] as $property) {
            if ($metadata->hasField($property)) {
                continue;
            }
            throw new LogicException(sprintf(
                'The entity "%s" extends "%s" without mapping its properties. The bundle no longer provides this mapping since 6.0.0: map an entity of your application and convert it from and to "%s" in your repository instead.',
                $className,
                $parentClass,
                $parentClass
            ));
        }
    }

    /**
     * @return key-of<self::MAPPED_PROPERTIES>|null
     */
    private function findParentClass(string $className): ?string
    {
        foreach (array_keys(self::MAPPED_PROPERTIES) as $parentClass) {
            if (is_subclass_of($className, $parentClass)) {
                return $parentClass;
            }
        }

        return null;
    }
}
