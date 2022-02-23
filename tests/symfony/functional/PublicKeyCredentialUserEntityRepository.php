<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Tests\Functional;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository as PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\PublicKeyCredentialUserEntity;

final class PublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepositoryInterface
{
    public function __construct(
        private CacheItemPoolInterface $cacheItemPool
    ) {
        $this->saveUserEntity(new User('admin', 'foo', 'Foo BAR (-_-)', null, ['ROLE_ADMIN', 'ROLE_USER']));
        $this->saveUserEntity(new User(
            'XY5nn3p_6olTLjoB2Jbb',
            '929fba2f-2361-4bc6-a917-bb76aa14c7f9',
            'Bennie Moneypenny',
            null,
            ['ROLE_ADMIN', 'ROLE_USER']
        ));
    }

    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
    {
        $item = $this->cacheItemPool->getItem('user-name' . Base64UrlSafe::encodeUnpadded($username));
        if (! $item->isHit()) {
            return null;
        }

        return $item->get();
    }

    public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
    {
        $item = $this->cacheItemPool->getItem('user-id' . Base64UrlSafe::encodeUnpadded($userHandle));
        if (! $item->isHit()) {
            return null;
        }

        return $item->get();
    }

    public function createUserEntity(
        string $username,
        string $displayName,
        ?string $icon
    ): PublicKeyCredentialUserEntity {
        return new User($username, Uuid::v4()->__toString(), $displayName, $icon);
    }

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void
    {
        if (! $userEntity instanceof User) {
            $userEntity = new User(
                $userEntity->getName(),
                $userEntity->getId(),
                $userEntity->getDisplayName(),
                $userEntity->getIcon()
            );
        }

        $item = $this->cacheItemPool->getItem('user-id' . Base64UrlSafe::encodeUnpadded($userEntity->getId()));
        $item->set($userEntity);
        $this->cacheItemPool->save($item);

        $item = $this->cacheItemPool->getItem('user-name' . Base64UrlSafe::encodeUnpadded($userEntity->getName()));
        $item->set($userEntity);
        $this->cacheItemPool->save($item);
    }
}
