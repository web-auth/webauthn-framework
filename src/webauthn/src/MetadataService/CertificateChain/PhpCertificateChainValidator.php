<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\CertificateChain;

use function array_slice;
use function count;
use function in_array;
use function parse_url;
use const PHP_EOL;
use const PHP_URL_SCHEME;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use function sprintf;
use Symfony\Component\Clock\NativeClock;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;
use Webauthn\Event\BeforeCertificateChainValidation;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\CertificateChainValidationFailed;
use Webauthn\Event\CertificateChainValidationSucceeded;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\Exception\CertificateChainException;
use Webauthn\Exception\CertificateRevocationListException;
use Webauthn\Exception\InvalidCertificateException;

final class PhpCertificateChainValidator implements CertificateChainValidator, CanDispatchEvents
{
    private const MAX_VALIDATION_LENGTH = 5;

    private readonly ClockInterface $clock;

    private EventDispatcherInterface $dispatcher;

    public function __construct(
        private readonly HttpClientInterface $client,
        null|ClockInterface $clock = null,
        private readonly bool $allowFailures = true
    ) {
        $this->clock = $clock ?? new NativeClock();
        $this->dispatcher = new NullEventDispatcher();
    }

    public static function create(
        HttpClientInterface $client,
        null|ClockInterface $clock = null,
        bool $allowFailures = true
    ): self {
        return new self($client, $clock, $allowFailures);
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->dispatcher = $eventDispatcher;
    }

    /**
     * @param string[] $untrustedCertificates
     * @param string[] $trustedCertificates
     */
    public function check(array $untrustedCertificates, array $trustedCertificates): void
    {
        foreach ($trustedCertificates as $trustedCertificate) {
            $this->dispatcher->dispatch(
                BeforeCertificateChainValidation::create($untrustedCertificates, $trustedCertificate)
            );
            try {
                if ($this->validateChain($untrustedCertificates, $trustedCertificate)) {
                    $this->dispatcher->dispatch(
                        CertificateChainValidationSucceeded::create($untrustedCertificates, $trustedCertificate)
                    );
                    return;
                }
            } catch (Throwable $exception) {
                $this->dispatcher->dispatch(
                    CertificateChainValidationFailed::create($untrustedCertificates, $trustedCertificate)
                );
                throw $exception;
            }
        }

        throw CertificateChainException::create($untrustedCertificates, $trustedCertificates);
    }

    /**
     * @param string[] $untrustedCertificates
     */
    private function validateChain(array $untrustedCertificates, string $trustedCertificate): bool
    {
        $untrustedCertificateObjects = array_map(
            static fn (string $cert): Certificate => Certificate::fromPEM(PEM::fromString($cert)),
            array_reverse($untrustedCertificates)
        );
        $trustedCertificateObject = Certificate::fromPEM(PEM::fromString($trustedCertificate));

        // The trust path and the authenticator certificate are the same
        if (count(
            $untrustedCertificateObjects
        ) === 1 && $untrustedCertificateObjects[0]->toPEM()->string() === $trustedCertificateObject->toPEM()->string()) {
            return true;
        }
        $uniqueCertificates = array_map(
            static fn (Certificate $cert): string => $cert->toPEM()
                ->string(),
            [...$untrustedCertificateObjects, $trustedCertificateObject]
        );
        count(array_unique($uniqueCertificates)) === count(
            $uniqueCertificates
        ) || throw CertificateChainException::create(
            $untrustedCertificates,
            [$trustedCertificate],
            'Invalid certificate chain with duplicated certificates.'
        );

        $path = $this->findCertificationPath($trustedCertificateObject, $untrustedCertificateObjects);
        if ($path === null) {
            return false;
        }

        foreach ($path as $certificate) {
            if ($this->isRevoked($certificate)) {
                throw CertificateChainException::create(
                    $untrustedCertificates,
                    [$trustedCertificate],
                    'Unable to validate the certificate chain. Revoked certificate found.'
                );
            }
        }

        return true;
    }

    /**
     * Returns the certification path that leads from the trust anchor to the end-entity certificate, or null when
     * the chain holds none.
     *
     * RFC 5280 makes the trust anchor an input of the path validation, not a certificate of the path, and a chain may
     * carry certificates above the one the trust anchor issued. The "x5c" of the FIDO Alliance metadata BLOB ends with
     * GlobalSign Root R46 cross-signed by GlobalSign Root CA - R3: the path stops below that cross-certificate when
     * the trust anchor is the self-signed R46, and goes through it when the trust anchor is R3. Each tail of the chain
     * is therefore tried in turn, from the end-entity certificate alone up to the whole chain. The first tail that
     * validates is the path: the certificates above it take part neither in the validation nor in the revocation
     * checks.
     *
     * The chain is walked in the order RFC 7515 and the attestation formats prescribe for "x5c", each certificate
     * followed by its issuer, and no path is built out of another order: a chain the client controls costs one attempt
     * per certificate, where a path builder would explore the combinations of its certificates.
     *
     * @param Certificate[] $certificates The chain from its topmost certificate down to the end-entity certificate
     *
     * @return Certificate[]|null
     */
    private function findCertificationPath(Certificate $trustAnchor, array $certificates): ?array
    {
        $numCerts = count($certificates);
        for ($length = 1; $length <= $numCerts; $length++) {
            $path = array_slice($certificates, -$length);
            if ($this->validateCertificates($trustAnchor, ...$path)) {
                return $path;
            }
        }

        return null;
    }

    private function isRevoked(Certificate $subject): bool
    {
        try {
            $csn = $subject->tbsCertificate()
                ->serialNumber();
        } catch (Throwable $e) {
            throw InvalidCertificateException::create(
                $subject->toPEM()
                    ->string(),
                sprintf('Failed to parse certificate: %s', $e->getMessage()),
                $e
            );
        }

        try {
            $urls = $this->getCrlUrlList($subject);
        } catch (Throwable $e) {
            if ($this->allowFailures) {
                return false;
            }
            throw InvalidCertificateException::create(
                $subject->toPEM()
                    ->string(),
                'Failed to get CRL distribution points: ' . $e->getMessage(),
                $e
            );
        }

        foreach ($urls as $url) {
            try {
                $revokedCertificates = $this->retrieveRevokedSerialNumbers($url);

                if (in_array($csn, $revokedCertificates, true)) {
                    return true;
                }
            } catch (Throwable $e) {
                if ($this->allowFailures) {
                    return false;
                }
                throw CertificateRevocationListException::create($url, sprintf(
                    'Failed to retrieve the CRL:' . PHP_EOL . '%s',
                    $e->getMessage()
                ), $e);
            }
        }
        return false;
    }

    private function validateCertificates(Certificate $trustAnchor, Certificate ...$certificates): bool
    {
        try {
            $config = PathValidationConfig::create($this->clock->now(), self::MAX_VALIDATION_LENGTH)->withTrustAnchor(
                $trustAnchor
            );
            CertificationPath::create(...$certificates)->validate($config);

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @return string[]
     */
    private function retrieveRevokedSerialNumbers(string $url): array
    {
        try {
            $crlData = $this->client->request('GET', $url)
                ->getContent();
            $crl = UnspecifiedType::fromDER($crlData)->asSequence();
            count($crl) === 3 || throw CertificateRevocationListException::create($url);
            $tbsCertList = $crl->at(0)
                ->asSequence();
            count($tbsCertList) >= 6 || throw CertificateRevocationListException::create($url);
            $list = $tbsCertList->at(5)
                ->asSequence();

            return array_map(static function (UnspecifiedType $r) use ($url): string {
                $sequence = $r->asSequence();
                count($sequence) >= 1 || throw CertificateRevocationListException::create($url);
                return $sequence->at(0)
                    ->asInteger()
                    ->number();
            }, $list->elements());
        } catch (Throwable $e) {
            throw CertificateRevocationListException::create($url, 'Failed to download the CRL', $e);
        }
    }

    /**
     * @return string[]
     */
    private function getCrlUrlList(Certificate $subject): array
    {
        try {
            $urls = [];

            $extensions = $subject->tbsCertificate()
                ->extensions();
            if ($extensions->hasCRLDistributionPoints()) {
                $crlDists = $extensions->crlDistributionPoints();
                foreach ($crlDists->distributionPoints() as $dist) {
                    $url = $dist->fullName()
                        ->names()
                        ->firstURI();
                    $scheme = parse_url($url, PHP_URL_SCHEME);
                    if (! in_array($scheme, ['http', 'https'], true)) {
                        continue;
                    }
                    $urls[] = $url;
                }
            }
            return $urls;
        } catch (Throwable $e) {
            throw InvalidCertificateException::create(
                $subject->toPEM()
                    ->string(),
                'Failed to get CRL distribution points from certificate: ' . $e->getMessage(),
                $e
            );
        }
    }
}
