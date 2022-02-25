<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

class DistantSingleMetadata extends SingleMetadata
{
    /**
     * @var array<string, mixed>
     */
    private array $additionalHeaders;

    public function __construct(
        private string $uri,
        bool $isBase64Encoded,
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory
    ) {
        parent::__construct('', $isBase64Encoded);
    }

    public function getMetadataStatement(): MetadataStatement
    {
        $this->data = $this->fetch();

        return parent::getMetadataStatement();
    }

    public function addHeaders(array $additionalHeaders): self
    {
        $this->additionalHeaders = $additionalHeaders;

        return $this;
    }

    public function addHeader(string $key, mixed $value): self
    {
        $this->additionalHeaders[$key] = $value;

        return $this;
    }

    private function fetch(): string
    {
        $request = $this->requestFactory->createRequest('GET', $this->uri);
        foreach ($this->additionalHeaders as $k => $v) {
            $request = $request->withHeader($k, $v);
        }
        $response = $this->httpClient->sendRequest($request);
        Assertion::eq(
            200,
            $response->getStatusCode(),
            sprintf('Unable to contact the server. Response code is %d', $response->getStatusCode())
        );
        $content = $response->getBody()
            ->getContents()
        ;
        Assertion::notEmpty($content, 'Unable to contact the server. The response has no content');

        return $content;
    }
}
