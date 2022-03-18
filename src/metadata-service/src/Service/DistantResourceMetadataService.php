<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use Assert\Assertion;
use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use function sprintf;
use Webauthn\MetadataService\Statement\MetadataStatement;

final class DistantResourceMetadataService implements MetadataService
{
    private ?MetadataStatement $statement = null;

    public function __construct(
        private RequestFactoryInterface $requestFactory,
        private ClientInterface $httpClient,
        private string $uri,
        private bool $isBase64Encoded = false,
        private array $additionalHeaderParameters = [],
    ) {
    }

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

        yield from [$this->statement->getAaguid()];
    }

    public function has(string $aaguid): bool
    {
        $this->loadData();

        return $aaguid === $this->statement->getAaguid();
    }

    public function get(string $aaguid): MetadataStatement
    {
        $this->loadData();

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
            $content = Base64::decode($content);
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
        Assertion::eq(
            200,
            $response->getStatusCode(),
            sprintf('Unable to contact the server. Response code is %d', $response->getStatusCode())
        );
        $response->getBody()
            ->rewind()
        ;
        $content = $response->getBody()
            ->getContents()
        ;
        Assertion::notEmpty($content, 'Unable to contact the server. The response has no content');

        return $content;
    }
}
