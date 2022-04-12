<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use function array_key_exists;
use Assert\Assertion;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use const JSON_THROW_ON_ERROR;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use function sprintf;
use Throwable;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;

final class FidoAllianceCompliantMetadataService implements MetadataService
{
    private bool $loaded = false;

    /**
     * @var MetadataStatement[]
     */
    private array $statements = [];

    /**
     * @var array<string, array<int, StatusReport>>
     */
    private array $statusReports = [];

    /**
     * @param array<string, mixed> $additionalHeaderParameters
     */
    public function __construct(
        private readonly RequestFactoryInterface $requestFactory,
        private readonly ClientInterface $httpClient,
        private readonly string $uri,
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
        array $additionalHeaderParameters = []
    ): self {
        return new self($requestFactory, $httpClient, $uri, $additionalHeaderParameters);
    }

    /**
     * @return string[]
     */
    public function list(): iterable
    {
        $this->loadData();

        yield from array_keys($this->statements);
    }

    public function has(string $aaguid): bool
    {
        $this->loadData();

        return array_key_exists($aaguid, $this->statements);
    }

    public function get(string $aaguid): MetadataStatement
    {
        $this->loadData();

        Assertion::keyExists(
            $this->statements,
            $aaguid,
            sprintf('The Metadata Statement with AAGUID "%s" is missing', $aaguid)
        );

        return $this->statements[$aaguid];
    }

    /**
     * @return StatusReport[]
     */
    public function getStatusReports(string $aaguid): iterable
    {
        $this->loadData();

        return $this->statusReports[$aaguid] ?? [];
    }

    private function loadData(): void
    {
        if ($this->loaded) {
            return;
        }

        $content = $this->fetch();
        $rootCertificates = [];
        try {
            $payload = $this->getJwsPayload($content, $rootCertificates);
            $data = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);

            foreach ($data['entries'] as $datum) {
                $entry = MetadataBLOBPayloadEntry::createFromArray($datum);

                $mds = $entry->getMetadataStatement();
                if ($mds !== null && $entry->getAaguid() !== null) {
                    $mds->setRootCertificates($rootCertificates);
                    $this->statements[$entry->getAaguid()] = $mds;
                    $this->statusReports[$entry->getAaguid()] = $entry->getStatusReports();
                }
            }
        } catch (Throwable) {
        }

        $this->loaded = true;
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

    /**
     * @param string[] $rootCertificates
     */
    private function getJwsPayload(string $token, array &$rootCertificates): string
    {
        $jws = (new CompactSerializer())->unserialize($token);
        Assertion::eq(
            1,
            $jws->countSignatures(),
            'Invalid response from the metadata service. Only one signature shall be present.'
        );
        $signature = $jws->getSignature(0);
        $payload = $jws->getPayload();
        Assertion::notEmpty($payload, 'Invalid response from the metadata service. The token payload is empty.');
        $header = $signature->getProtectedHeader();
        Assertion::keyExists($header, 'alg', 'The "alg" parameter is missing.');
        //Assertion::eq($header['alg'], 'ES256', 'The expected "alg" parameter value should be "ES256".');
        Assertion::keyExists($header, 'x5c', 'The "x5c" parameter is missing.');
        Assertion::isArray($header['x5c'], 'The "x5c" parameter should be an array.');
        $key = JWKFactory::createFromX5C($header['x5c']);
        $rootCertificates = $header['x5c'];

        $verifier = new JWSVerifier(new AlgorithmManager([new ES256(), new RS256()]));
        $isValid = $verifier->verifyWithKey($jws, $key, 0);
        Assertion::true($isValid, 'Invalid response from the metadata service. The token signature is invalid.');
        $payload = $jws->getPayload();
        Assertion::notNull($payload, 'Invalid response from the metadata service. The payload is missing.');

        return $payload;
    }
}
