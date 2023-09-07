<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\Bundle\Repository\CanSaveCredentialSource;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

final class PublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface, CanSaveCredentialSource
{
    public function __construct(
        private readonly CacheItemPoolInterface $cacheItemPool
    ) {
        $publicKeyCredentialSource1 = PublicKeyCredentialSource::create(
            base64_decode(
                'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                true
            ),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            base64_decode(
                'pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=',
                true
            ),
            'foo',
            100
        );
        $this->saveCredentialSource($publicKeyCredentialSource1);
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $item = $this->cacheItemPool->getItem('pks-' . Base64UrlSafe::encodeUnpadded($publicKeyCredentialId));
        if (! $item->isHit()) {
            return null;
        }

        return $item->get();
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        $item = $this->cacheItemPool->getItem(
            'user-pks-' . Base64UrlSafe::encodeUnpadded($publicKeyCredentialUserEntity->id)
        );
        if (! $item->isHit()) {
            return [];
        }

        return $item->get();
    }

    public function clearCredentials(): void
    {
        $this->cacheItemPool->clear();
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $item = $this->cacheItemPool->getItem(
            'pks-' . Base64UrlSafe::encodeUnpadded($publicKeyCredentialSource->publicKeyCredentialId)
        );
        $item->set($publicKeyCredentialSource);
        $this->cacheItemPool->save($item);

        $item = $this->cacheItemPool->getItem(
            'user-pks-' . Base64UrlSafe::encodeUnpadded($publicKeyCredentialSource->userHandle)
        );
        $pks = [];
        if ($item->isHit()) {
            $pks = $item->get();
        }
        $pks[] = $publicKeyCredentialSource;
        $item->set($pks);
        $this->cacheItemPool->save($item);
    }

    public function removeCredentialWithId(string $id): void
    {
        $this->cacheItemPool->deleteItem('pks-' . $id);
    }
}
