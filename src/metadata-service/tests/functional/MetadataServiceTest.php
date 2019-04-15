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

namespace Webauthn\Tests\Functional;

use Http\Client\Curl\Client;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Webauthn\MetadataService\MetadataServiceCaller;

/**
 * @group functional
 * @group Fido2
 * @group TOC
 */
class MetadataServiceTest extends AbstractTestCase
{
    /**
     * @test
     */
    public function theTocCanBeRetrieved(): void
    {
        $cacheAdapter = new FilesystemAdapter();
        $cacheAdapter->clear();
        $service = new MetadataServiceCaller(
            new Client(),
            new Psr17Factory(),
            '511960cbb24588a3299db1d2dee6e040c133e1d8ad2cde94',
            $cacheAdapter
        );

        $data = $service->getMetadataTOCPayload();
        foreach ($data->getEntries() as $entry) {
            if (null !== $entry->getAaguid()) {
                dump($entry->getAaguid());
                $service->getMetadataTOCPayloadEntry($entry->getAaguid());
            }
        }
    }
}
