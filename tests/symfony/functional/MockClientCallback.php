<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use RuntimeException;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * @internal
 */
final class MockClientCallback
{
    /**
     * @var ResponseInterface[]
     */
    private array $responses = [];

    public function __invoke(string $method, string $url): ?ResponseInterface
    {
        $key = $method . '-' . $url;
        if (! isset($this->responses[$key])) {
            throw new RuntimeException(sprintf(
                'Unable to find a response for a %s request to the URL %s',
                $method,
                $url
            ));
        }

        return $this->responses[$key];
    }

    /**
     * @param ResponseInterface[] $responses
     */
    public function addResponses(array $responses): self
    {
        foreach ($responses as $id => $response) {
            $this->responses[$id] = $response;
        }

        return $this;
    }
}
