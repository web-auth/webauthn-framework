<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use Http\Message\RequestMatcher\RequestMatcher;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\Stream;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;

trait MockedMappedResponseTrait
{
    protected function prepareResponsesMap(ClientInterface $client): void
    {
        $requestMatcher = new RequestMatcher();
        $map = $this->getResponsesMap();
        $client->on($requestMatcher, function (RequestInterface $request) use ($map) {
            if (! isset($map[$request->getUri()->__toString()])) {
                return new Response(404);
            }

            $body = Stream::create($map[$request->getUri()->__toString()]);
            $body->rewind();

            return new Response(200, [], $body);
        });
    }

    abstract protected function getResponsesMap(): iterable;
}
