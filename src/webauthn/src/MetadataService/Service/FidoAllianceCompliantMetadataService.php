<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use function array_key_exists;
use InvalidArgumentException;
use function is_array;
use function is_string;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use LogicException;
use Psr\EventDispatcher\EventDispatcherInterface;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use function sprintf;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\MetadataStatementFound;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\Exception\MetadataStatementLoadingException;
use Webauthn\Exception\MissingMetadataStatementException;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;

final class FidoAllianceCompliantMetadataService implements MetadataService, CanDispatchEvents
{
    private bool $loaded = false;

    /**
     * @var MetadataStatement[]
     */
    private array $statements = [];

    /**
     * @var array<string, StatusReport[]>
     */
    private array $statusReports = [];

    private EventDispatcherInterface $dispatcher;

    private readonly SerializerInterface $serializer;

    private readonly CertificateChainValidator $certificateChainValidator;

    private readonly string $rootCertificateUri;

    /**
     * The BLOB is trusted only once its signing certificate chain validates against the root certificate, as the
     * metadata BLOB processing rules of the FIDO Metadata Service specification require. The certificate chain
     * validator and the root certificate URI are therefore required: their null defaults only keep the signature
     * unchanged until 6.0.
     *
     * @param array<string, mixed> $additionalHeaderParameters
     */
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly string $uri,
        private readonly array $additionalHeaderParameters = [],
        ?CertificateChainValidator $certificateChainValidator = null,
        ?string $rootCertificateUri = null,
        ?SerializerInterface $serializer = null,
    ) {
        if (! class_exists(CompactSerializer::class)) {
            throw new LogicException(
                'The "web-token/jwt-library" package is required to use this service. Please run "composer require web-token/jwt-library".'
            );
        }
        $certificateChainValidator !== null || throw new InvalidArgumentException(
            'A certificate chain validator is required to verify the metadata BLOB against its root certificate.'
        );
        $rootCertificateUri !== null || throw new InvalidArgumentException(
            'The root certificate URI is required to verify the metadata BLOB. For the FIDO Alliance Metadata Service, it is "https://secure.globalsign.com/cacert/root-r3.crt".'
        );
        $this->certificateChainValidator = $certificateChainValidator;
        $this->rootCertificateUri = $rootCertificateUri;
        $this->serializer = $serializer ?? (new WebauthnSerializerFactory(
            AttestationStatementSupportManager::create()
        ))->create();
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
        HttpClientInterface $httpClient,
        string $uri,
        array $additionalHeaderParameters = [],
        ?CertificateChainValidator $certificateChainValidator = null,
        ?string $rootCertificateUri = null,
        ?SerializerInterface $serializer = null,
    ): self {
        return new self(
            $httpClient,
            $uri,
            $additionalHeaderParameters,
            $certificateChainValidator,
            $rootCertificateUri,
            $serializer,
        );
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
        array_key_exists($aaguid, $this->statements) || throw MissingMetadataStatementException::create($aaguid);
        $mds = $this->statements[$aaguid];
        $this->dispatcher->dispatch(MetadataStatementFound::create($mds));

        return $mds;
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

        $content = $this->fetch($this->uri, $this->additionalHeaderParameters);
        try {
            $payload = $this->getJwsPayload($content);
            /** @var MetadataBLOBPayload $blob */
            $blob = $this->serializer->deserialize($payload, MetadataBLOBPayload::class, JsonEncoder::FORMAT);
            foreach ($blob->entries as $entry) {
                $mds = $entry->metadataStatement;
                if ($mds !== null && $entry->aaguid !== null) {
                    $this->statements[$entry->aaguid] = $mds;
                    $this->statusReports[$entry->aaguid] = $entry->statusReports;
                }
            }
        } catch (Throwable) {
            // Nothing to do
        } finally {
            $this->loaded = true;
        }
    }

    /**
     * @param array<string, mixed> $headerParameters
     */
    private function fetch(string $uri, array $headerParameters): string
    {
        $response = $this->httpClient->request('GET', $uri, [
            'headers' => $headerParameters,
        ]);
        $response->getStatusCode() === 200 || throw MetadataStatementLoadingException::create(sprintf(
            'Unable to contact the server. Response code is %d',
            $response->getStatusCode()
        ));

        $content = $response->getContent();
        $content !== '' || throw MetadataStatementLoadingException::create(
            'Unable to contact the server. The response has no content'
        );

        return $content;
    }

    /**
     * The certificates of the "x5c" header are decoded once, from the strict base64 encoding of their DER that RFC
     * 7515 (section 4.1.6) requires. The chain validator receives PEM built from those bytes, and the signature is
     * verified with the public key that pki-framework reads from the same bytes of the first certificate. An entry
     * that holds anything else, such as PEM text with several blocks, is refused, so it cannot show one certificate
     * to the chain validation and another one to the signature verification.
     */
    private function getJwsPayload(string $token): string
    {
        $jws = (new CompactSerializer())->unserialize($token);
        $jws->countSignatures() === 1 || throw MetadataStatementLoadingException::create(
            'Invalid response from the metadata service. Only one signature shall be present.'
        );
        $payload = $jws->getPayload();
        ($payload !== null && $payload !== '') || throw MetadataStatementLoadingException::create(
            'Invalid response from the metadata service. The token payload is empty.'
        );
        $header = $jws->getSignature(0)
            ->getProtectedHeader();
        array_key_exists('alg', $header) || throw MetadataStatementLoadingException::create(
            'The "alg" parameter is missing.'
        );
        array_key_exists('x5c', $header) || throw MetadataStatementLoadingException::create(
            'The "x5c" parameter is missing.'
        );
        (is_array($header['x5c']) && $header['x5c'] !== [] && array_is_list(
            $header['x5c']
        )) || throw MetadataStatementLoadingException::create('The "x5c" parameter should be a non-empty list.');
        $certificates = array_map(self::decodeCertificate(...), $header['x5c']);

        $this->certificateChainValidator->check(
            array_map(
                static fn (string $certificate): string => PEM::create(PEM::TYPE_CERTIFICATE, $certificate)->string(),
                $certificates
            ),
            [$this->getRootCertificate()]
        );

        $key = JWKFactory::createFromKey(
            Certificate::fromDER($certificates[0])->tbsCertificate()->subjectPublicKeyInfo()->toPEM()->string()
        );
        $verifier = new JWSVerifier(new AlgorithmManager([new ES256(), new RS256()]));
        $verifier->verifyWithKey($jws, $key, 0) || throw MetadataStatementLoadingException::create(
            'Invalid response from the metadata service. The token signature is invalid.'
        );

        return $payload;
    }

    /**
     * Returns the DER of a certificate of the "x5c" header, which must be its base64 encoding and nothing else.
     */
    private static function decodeCertificate(mixed $encodedCertificate): string
    {
        is_string($encodedCertificate) || throw MetadataStatementLoadingException::create(
            'Invalid response from the metadata service. The "x5c" parameter shall only contain strings.'
        );
        $certificate = base64_decode($encodedCertificate, true);
        ($certificate !== false && $certificate !== '' && base64_encode(
            $certificate
        ) === $encodedCertificate) || throw MetadataStatementLoadingException::create(
            'Invalid response from the metadata service. Each "x5c" entry shall be a base64-encoded DER certificate.'
        );

        return $certificate;
    }

    /**
     * The root certificate is served either as DER, as GlobalSign does for the FIDO Alliance Metadata Service, or as
     * a PEM block, possibly preceded by text. Its DER is extracted and handed over in a PEM block built from it.
     */
    private function getRootCertificate(): string
    {
        $rootCertificate = $this->fetch($this->rootCertificateUri, []);
        if (str_contains($rootCertificate, '-----BEGIN ')) {
            $pem = PEM::fromString($rootCertificate);
            $pem->type() === PEM::TYPE_CERTIFICATE || throw MetadataStatementLoadingException::create(
                'The root certificate of the metadata service is not a certificate.'
            );
            $rootCertificate = $pem->data();
        }

        return PEM::create(PEM::TYPE_CERTIFICATE, $rootCertificate)->string();
    }
}
