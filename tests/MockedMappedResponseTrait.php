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

use Http\Message\RequestMatcher\RequestMatcher;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

trait MockedMappedResponseTrait
{
    protected function prepareResponsesMap(ClientInterface $client): void
    {
        $requestMatcher = new RequestMatcher();
        $map = $this->getResponsesMap();
        $client->on($requestMatcher, function (RequestInterface $request) use ($map) {
            $response = $this->createMock(ResponseInterface::class);

            if (!isset($map[$request->getUri()->getPath()])) {
                $response
                    ->method('getStatusCode')
                    ->willReturn(404)
                ;

                return $response->reveal();
            }

            $body = $this->createMock(StreamInterface::class);
            $body
                ->method('getContents')
                ->willReturn($map[$request->getUri()->getPath()])
            ;
            $response
                ->expects(static::atLeastOnce())
                ->method('getStatusCode')
                ->willReturn(200)
            ;
            $response
                ->expects(static::atLeastOnce())
                ->method('getBody')
                ->willReturn($body)
            ;

            return $response;
        });
    }

    abstract protected function getResponsesMap(): array;
}
