<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use function count;
use const E_USER_DEPRECATED;
use InvalidArgumentException;
use function is_array;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;
use const JSON_THROW_ON_ERROR;
use League\Uri\UriString;
use LogicException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use const PHP_QUERY_RFC3986;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;
use Webauthn\CertificateToolbox;

class MetadataService
{
    private array $additionalQueryStringValues;

    private LoggerInterface $logger;

    public function __construct(
        private string $serviceUri,
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        array $additionalQueryStringValues = [],
        private array $additionalHeaders = [],
        ?LoggerInterface $logger = null
    ) {
        if (count($additionalQueryStringValues) !== 0) {
            @trigger_error(
                'The argument "additionalQueryStringValues" is deprecated since version 3.3 and will be removed in 4.0. Please set an empty array instead and us the method `addQueryStringValues`.',
                E_USER_DEPRECATED
            );
        }
        if (count($additionalQueryStringValues) !== 0) {
            @trigger_error(
                'The argument "additionalHeaders" is deprecated since version 3.3 and will be removed in 4.0. Please set an empty array instead and us the method `addHeaders`.',
                E_USER_DEPRECATED
            );
        }
        if ($logger !== null) {
            @trigger_error(
                'The argument "logger" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setLogger" instead.',
                E_USER_DEPRECATED
            );
        }
        $this->additionalQueryStringValues = $additionalQueryStringValues;
        $this->logger = $logger ?? new NullLogger();
    }

    public function addQueryStringValues(array $additionalQueryStringValues): self
    {
        $this->additionalQueryStringValues = $additionalQueryStringValues;

        return $this;
    }

    public function addHeaders(array $additionalHeaders): self
    {
        $this->additionalHeaders = $additionalHeaders;

        return $this;
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function has(string $aaguid): bool
    {
        try {
            $toc = $this->fetchMetadataTOCPayload();
        } catch (Throwable) {
            return false;
        }
        foreach ($toc->getEntries() as $entry) {
            if ($entry->getAaguid() === $aaguid && $entry->getUrl() !== null) {
                return true;
            }
        }

        return false;
    }

    public function get(string $aaguid): MetadataStatement
    {
        $toc = $this->fetchMetadataTOCPayload();
        foreach ($toc->getEntries() as $entry) {
            if ($entry->getAaguid() === $aaguid && $entry->getUrl() !== null) {
                $mds = $this->fetchMetadataStatementFor($entry);
                $mds
                    ->setStatusReports($entry->getStatusReports())
                    ->setRootCertificates($toc->getRootCertificates())
                ;

                return $mds;
            }
        }

        throw new InvalidArgumentException(sprintf('The Metadata Statement with AAGUID "%s" is missing', $aaguid));
    }

    /**
     * @deprecated This method is deprecated since v3.3 and will be removed in v4.0
     */
    public function getMetadataStatementFor(
        MetadataTOCPayloadEntry $entry,
        string $hashingFunction = 'sha256'
    ): MetadataStatement {
        return $this->fetchMetadataStatementFor($entry, $hashingFunction);
    }

    public function fetchMetadataStatementFor(
        MetadataTOCPayloadEntry $entry,
        string $hashingFunction = 'sha256'
    ): MetadataStatement {
        $this->logger->info('Trying to get the metadata statement for a given entry', [
            'entry' => $entry,
        ]);
        try {
            $hash = $entry->getHash();
            $url = $entry->getUrl();
            if ($hash === null || $url === null) {
                throw new LogicException('The Metadata Statement has not been published');
            }
            $uri = $this->buildUri($url);
            $result = $this->fetchMetadataStatement($uri, true, $hash, $hashingFunction);
            $this->logger->info('The metadata statement exists');
            $this->logger->debug('Metadata Statement', [
                'mds' => $result,
            ]);

            return $result;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    /**
     * @deprecated This method is deprecated since v3.3 and will be removed in v4.0
     */
    public function getMetadataTOCPayload(): MetadataTOCPayload
    {
        return $this->fetchMetadataTOCPayload();
    }

    private function fetchMetadataTOCPayload(): MetadataTOCPayload
    {
        $this->logger->info('Trying to get the metadata service TOC payload');
        try {
            $uri = $this->buildUri($this->serviceUri);
            $toc = $this->fetchTableOfContent($uri);
            $this->logger->info('The TOC payload has been received');
            $this->logger->debug('TOC payload', [
                'toc' => $toc,
            ]);

            return $toc;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    private function buildUri(string $uri): string
    {
        $parsedUri = UriString::parse($uri);
        $queryString = $parsedUri['query'];
        $query = [];
        if ($queryString !== null) {
            parse_str($queryString, $query);
        }
        foreach ($this->additionalQueryStringValues as $k => $v) {
            if (! isset($query[$k])) {
                $query[$k] = $v;
                continue;
            }
            if (! is_array($query[$k])) {
                $query[$k] = [$query[$k], $v];
                continue;
            }
            $query[$k][] = $v;
        }
        $parsedUri['query'] = count($query) === 0 ? null : http_build_query($query, '', '&', PHP_QUERY_RFC3986);

        return UriString::build($parsedUri);
    }

    private function fetchTableOfContent(string $uri): MetadataTOCPayload
    {
        $content = $this->fetch($uri);
        $rootCertificates = [];
        $payload = $this->getJwsPayload($content, $rootCertificates);
        $data = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);

        $toc = MetadataTOCPayload::createFromArray($data);
        $toc->setRootCertificates($rootCertificates);

        return $toc;
    }

    private function fetchMetadataStatement(
        string $uri,
        bool $isBase64UrlEncoded,
        string $hash = '',
        string $hashingFunction = 'sha256'
    ): MetadataStatement {
        $payload = $this->fetch($uri);
        if ($hash !== '') {
            Assertion::true(
                hash_equals($hash, hash($hashingFunction, $payload, true)),
                'The hash cannot be verified. The metadata statement shall be rejected'
            );
        }
        $json = $isBase64UrlEncoded ? Base64UrlSafe::decode($payload) : $payload;
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        return MetadataStatement::createFromArray($data);
    }

    private function fetch(string $uri): string
    {
        $request = $this->requestFactory->createRequest('GET', $uri);
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
        Assertion::eq($header['alg'], 'ES256', 'The expected "alg" parameter value should be "ES256".');
        Assertion::keyExists($header, 'x5c', 'The "x5c" parameter is missing.');
        Assertion::isArray($header['x5c'], 'The "x5c" parameter should be an array.');
        $key = JWKFactory::createFromX5C($header['x5c']);
        $rootCertificates = array_map(static function (string $x509): string {
            return CertificateToolbox::fixPEMStructure($x509);
        }, $header['x5c']);
        $algorithm = new ES256();
        $isValid = $algorithm->verify(
            $key,
            $signature->getEncodedProtectedHeader() . '.' . $jws->getEncodedPayload(),
            $signature->getSignature()
        );
        Assertion::true($isValid, 'Invalid response from the metadata service. The token signature is invalid.');

        return $jws->getPayload();
    }
}
