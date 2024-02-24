<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use LogicException;
use Psr\Http\Client\ClientInterface as Psr18ClientInterface;
use Psr\Http\Message\RequestFactoryInterface as Psr17RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface as Psr17ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface as Psr17StreamFactoryInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;
use const PHP_QUERY_RFC3986;

class Psr18HttpClient implements HttpClientInterface
{
    private array $options = [];

    public function __construct(
        private readonly Psr18ClientInterface $client,
        private readonly Psr17RequestFactoryInterface $requestFactory,
        private readonly Psr17StreamFactoryInterface $streamFactory,
    ) {
    }

    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        $baseUri = $options['base_uri'] ?? '';
        $query = $options['query'] ?? [];
        if ($query) {
            $url .= (! str_contains($url, '?') ? '?' : '&') . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        }
        $request = $this->requestFactory->createRequest($method, $baseUri . $url);
        $body = $options['body'] ?? null;
        if ($body !== null) {
            $request = $request->withBody($this->streamFactory->createStream($body));
        }
        foreach ($this->options as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        foreach ($options['headers'] ?? [] as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        $response = $this->client->sendRequest($request);

        return static::fromPsr17($response);
    }

    /**
     * @param ResponseInterface|iterable<array-key, ResponseInterface> $responses
     */
    public function stream(iterable|ResponseInterface $responses, float $timeout = null): ResponseStreamInterface
    {
        throw new LogicException('Not implemented');
    }

    public function withOptions(array $options): static
    {
        $this->options = $options;
        return $this;
    }

    protected static function fromPsr17(Psr17ResponseInterface $response): ResponseInterface
    {
        $headers = $response->getHeaders();
        $content = $response->getBody()
            ->getContents();
        $status = $response->getStatusCode();

        return new class($status, $headers, $content) implements ResponseInterface {
            public function __construct(
                private readonly int $status,
                private readonly array $headers,
                private readonly string $content,
            ) {
            }

            public function getStatusCode(): int
            {
                return $this->status;
            }

            public function getHeaders(bool $throw = true): array
            {
                return $this->headers;
            }

            public function getContent(bool $throw = true): string
            {
                return $this->content;
            }

            public function toArray(bool $throw = true): array
            {
                return json_decode($this->content, true);
            }

            public function cancel(): void
            {
                // noop
            }

            public function getInfo(string $type = null): mixed
            {
                return null;
            }
        };
    }
}
