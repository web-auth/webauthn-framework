<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use function sprintf;

final class CacheStorage implements OptionsStorage
{
    private const CACHE_PARAMETER = 'WEBAUTHN_PUBLIC_KEY_OPTIONS';

    public function __construct(
        private readonly CacheItemPoolInterface $cache
    ) {
    }

    public function store(Item $item): void
    {
        $key = sprintf(
            '%s-%s',
            self::CACHE_PARAMETER,
            hash('sha512', $item->getPublicKeyCredentialOptions()->challenge)
        );

        $cacheItem = $this->cache->getItem($key);
        $cacheItem->set($item);
        $this->cache->save($cacheItem);
    }

    public function get(string|null $challenge = null): Item
    {
        if ($challenge === null) {
            throw new BadRequestHttpException('No public key credential options available.');
        }
        $key = sprintf('%s-%s', self::CACHE_PARAMETER, hash('sha512', $challenge));
        $cacheItem = $this->cache->getItem($key);
        if (! $cacheItem->isHit()) {
            throw new BadRequestHttpException('No public key credential options available.');
        }
        $item = $cacheItem->get();
        $this->cache->deleteItem($key);
        if (! $item instanceof Item) {
            throw new BadRequestHttpException('No public key credential options available.');
        }

        return $item;
    }
}
