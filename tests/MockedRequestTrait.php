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

namespace Webauthn\Tests;

use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

trait MockedRequestTrait
{
    protected function createRequestWithHost(string $host): MockObject
    {
        $uri = $this->createMock(UriInterface::class);
        $uri
            ->method('getHost')
            ->willReturn($host)
        ;
        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->method('getUri')
            ->willReturn($uri)
        ;

        return $request;
    }

    abstract protected function createMock(string $originalClassName): MockObject;
}
