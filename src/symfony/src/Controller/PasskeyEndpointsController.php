<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\PasskeyEndpointsResponse;

/**
 * Controller exposing the .well-known/passkey-endpoints endpoint.
 *
 * @see https://w3c.github.io/webappsec-passkey-endpoints/
 */
final readonly class PasskeyEndpointsController
{
    public function __construct(
        private PasskeyEndpointsResponse $passkeyEndpoints,
        private SerializerInterface $serializer
    ) {
    }

    public function __invoke(): JsonResponse
    {
        $endpoints = $this->serializer->serialize($this->passkeyEndpoints, 'json', [
            AbstractObjectNormalizer::PRESERVE_EMPTY_OBJECTS => true,
        ]);

        return new JsonResponse($endpoints, 200, [], true);
    }
}
