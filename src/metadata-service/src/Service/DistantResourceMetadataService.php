<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use ParagonIE\ConstantTime\Base64;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use function sprintf;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\MetadataStatementFound;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Exception\MissingMetadataStatementException;
use Webauthn\MetadataService\Statement\MetadataStatement;

final class DistantResourceMetadataService implements MetadataService, CanDispatchEvents
{
    private ?MetadataStatement $statement = null;

    private EventDispatcherInterface $dispatcher;

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
        $this->dispatcher = new NullEventDispatcher();
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->dispatcher = $eventDispatcher;
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
        $this->statement !== null || throw MetadataStatementLoadingException::create(
            'Unable to load the metadata statement'
        );
        $aaguid = $this->statement->getAaguid();
        if ($aaguid === null) {
            yield from [];
        } else {
            yield from [$aaguid];
        }
    }

    public function has(string $aaguid): bool
    {
        $this->loadData();
        $this->statement !== null || throw MetadataStatementLoadingException::create(
            'Unable to load the metadata statement'
        );

        return $aaguid === $this->statement->getAaguid();
    }

    public function get(string $aaguid): MetadataStatement
    {
        $this->loadData();
        $this->statement !== null || throw MetadataStatementLoadingException::create(
            'Unable to load the metadata statement'
        );

        if ($aaguid === $this->statement->getAaguid()) {
            $this->dispatcher->dispatch(MetadataStatementFound::create($this->statement));

            return $this->statement;
        }

        throw MissingMetadataStatementException::create($aaguid);
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
        $response->getStatusCode() === 200 || throw MetadataStatementLoadingException::create(sprintf(
            'Unable to contact the server. Response code is %d',
            $response->getStatusCode()
        ));
        $response->getBody()
            ->rewind();
        $content = $response->getBody()
            ->getContents();
        $content !== '' || throw MetadataStatementLoadingException::create(
            'Unable to contact the server. The response has no content'
        );

        return $content;
    }
}
