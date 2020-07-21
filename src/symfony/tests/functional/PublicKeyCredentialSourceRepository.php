<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional;

use Base64Url\Base64Url;
use Psr\Cache\CacheItemPoolInterface;
use Ramsey\Uuid\Uuid;
use function Safe\base64_decode;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

final class PublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface
{
    private $cacheItemPool;

    public function __construct(CacheItemPoolInterface $cacheItemPool)
    {
        $this->cacheItemPool = $cacheItemPool;
        $publicKeyCredentialSource1 = new PublicKeyCredentialSource(
            base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            new EmptyTrustPath(),
            Uuid::fromBytes(base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true)),
            base64_decode('pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=', true),
            'foo',
            100
        );
        $this->saveCredentialSource($publicKeyCredentialSource1);
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $item = $this->cacheItemPool->getItem('pks-'.Base64Url::encode($publicKeyCredentialId));
        if (!$item->isHit()) {
            return null;
        }

        return $item->get();
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        $item = $this->cacheItemPool->getItem('user-pks-'.Base64Url::encode($publicKeyCredentialUserEntity->getId()));
        if (!$item->isHit()) {
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
        $item = $this->cacheItemPool->getItem('pks-'.Base64Url::encode($publicKeyCredentialSource->getPublicKeyCredentialId()));
        $item->set($publicKeyCredentialSource);
        $this->cacheItemPool->save($item);

        $item = $this->cacheItemPool->getItem('user-pks-'.Base64Url::encode($publicKeyCredentialSource->getUserHandle()));
        $pks = [];
        if ($item->isHit()) {
            $pks = $item->get();
        }
        $pks[] = $publicKeyCredentialSource;
        $item->set($pks);
        $this->cacheItemPool->save($item);
    }
}
