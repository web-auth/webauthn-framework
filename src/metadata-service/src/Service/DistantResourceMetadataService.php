<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use function sprintf;
use Webauthn\MetadataService\Statement\MetadataStatement;

final class DistantResourceMetadataService implements MetadataService
{
    private ?MetadataStatement $statement = null;

    /**
     * @param array<string, string> $additionalHeaderParameters
     */
    public function __construct(
        private readonly RequestFactoryInterface $requestFactory,
        private readonly ClientInterface $httpClient,
        private readonly string $uri,
        private readonly bool $isBase64Encoded = false,
        private readonly array $additionalHeaderParameters = [],
    ) {
    }

    /**
     * @param array<string, mixed> $additionalHeaderParameters
     */
    public static function create(
        RequestFactoryInterface $requestFactory,
        ClientInterface $httpClient,
        string $uri,
        bool $isBase64Encoded = false,
        array $additionalHeaderParameters = []
    ): self {
        return new self($requestFactory, $httpClient, $uri, $isBase64Encoded, $additionalHeaderParameters);
    }

    public function list(): iterable
    {
        $this->loadData();
        $this->statement !== null || throw new InvalidArgumentException('Unable to load the metadata statement');
        $aaguid = $this->statement->getAaguid();
        $aaguid !== null || throw new InvalidArgumentException('Unable to load the metadata statement');

        yield from [$aaguid];
    }

    public function has(string $aaguid): bool
    {
        $this->loadData();
        $this->statement !== null || throw new InvalidArgumentException('Unable to load the metadata statement');

        return $aaguid === $this->statement->getAaguid();
    }

    public function get(string $aaguid): MetadataStatement
    {
        $this->loadData();
        $this->statement !== null || throw new InvalidArgumentException('Unable to load the metadata statement');

        if ($aaguid === $this->statement->getAaguid()) {
            return $this->statement;
        }

        throw new InvalidArgumentException(sprintf('The Metadata Statement with AAGUID "%s" is missing', $aaguid));
    }

    private function loadData(): void
    {
        if ($this->statement !== null) {
            return;
        }

        $content = $this->fetch();
        if ($this->isBase64Encoded) {
            $content = Base64::decode($content, true);
        }
        $this->statement = MetadataStatement::createFromString($content);
    }

    private function fetch(): string
    {
        $request = $this->requestFactory->createRequest('GET', $this->uri);
        foreach ($this->additionalHeaderParameters as $k => $v) {
            $request = $request->withHeader($k, $v);
        }
        $response = $this->httpClient->sendRequest($request);
        $response->getStatusCode() === 200 || throw new InvalidArgumentException(sprintf(
            'Unable to contact the server. Response code is %d',
            $response->getStatusCode()
        ));
        $response->getBody()
            ->rewind();
        $content = $response->getBody()
            ->getContents();
        $content !== '' || throw new InvalidArgumentException(
            'Unable to contact the server. The response has no content'
        );

        return $content;
    }
}
