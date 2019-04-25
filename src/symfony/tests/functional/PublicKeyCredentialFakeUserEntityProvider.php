<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional;

use Faker\Factory;
use Psr\Cache\CacheItemPoolInterface;
use Ramsey\Uuid\Uuid;
use Webauthn\Bundle\Model\PublicKeyCredentialFakeUserEntity;
use Webauthn\Bundle\Provider\FakePublicKeyCredentialUserEntityProvider;
use Webauthn\PublicKeyCredentialDescriptor;

final class PublicKeyCredentialFakeUserEntityProvider implements FakePublicKeyCredentialUserEntityProvider
{
    /**
     * @var CacheItemPoolInterface
     */
    private $cacheItemPool;

    public function __construct(CacheItemPoolInterface $cacheItemPool)
    {
        $this->cacheItemPool = $cacheItemPool;
    }

    public function getFakeUserEntityFor(string $username): PublicKeyCredentialFakeUserEntity
    {
        $cacheItem = $this->cacheItemPool->getItem('FAKE_USER_ENTITIES-'.$username);
        if ($cacheItem->isHit()) {
            return $cacheItem->get();
        }

        $fakeUserEntity = $this->generateFakeUserEntityFor($username);
        $cacheItem->set($fakeUserEntity);
        $this->cacheItemPool->save($cacheItem);

        return $fakeUserEntity;
    }

    public function generateFakeUserEntityFor(string $username): PublicKeyCredentialFakeUserEntity
    {
        $nbCredentials = random_int(1, 6);
        $credentials = [];
        for ($i = 0; $i < $nbCredentials; ++$i) {
            $credentials[] = new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                random_bytes(32)
            );
        }
        $factory = Factory::create();

        return new PublicKeyCredentialFakeUserEntity(
            $username,
            Uuid::uuid4()->toString(),
            $factory->name,
            $credentials
        );
    }
}
