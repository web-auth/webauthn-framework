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

use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Uri;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ServerRequestInterface;

trait MockedRequestTrait
{
    protected function createRequestWithHost(string $host): ServerRequestInterface
    {
        $uri = new Uri('https://'.$host);

        return new ServerRequest('POST', $uri);
    }

    abstract protected function createMock(string $originalClassName): MockObject;
}
