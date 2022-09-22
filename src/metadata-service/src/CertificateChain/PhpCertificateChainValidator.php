<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\CertificateChain;

use function count;
use DateTimeZone;
use function in_array;
use InvalidArgumentException;
use Lcobucci\Clock\Clock;
use function parse_url;
use const PHP_EOL;
use const PHP_URL_SCHEME;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;
use Throwable;

/**
 * @final
 */
class PhpCertificateChainValidator implements CertificateChainValidator
{
    private const MAX_VALIDATION_LENGTH = 5;

    private readonly Clock|ClockInterface $clock;

    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        null|Clock|ClockInterface $clock = null,
        private readonly bool $allowFailures = true
    ) {
        if ($clock === null) {
            $clock = new NativeClock(new DateTimeZone('UTC'));
        } elseif ($clock instanceof Clock) {
            @trigger_deprecation(
                'web-auth/metadata-service',
                '4.3.0',
                'Using "%s" is deprecated, use "%s" instead.',
                'lcobucci/clock',
                'symfony/clock'
            );
        }
        $this->clock = $clock;
    }

    /**
     * @param string[] $untrustedCertificates
     * @param string[] $trustedCertificates
     */
    public function check(array $untrustedCertificates, array $trustedCertificates): void
    {
        foreach ($trustedCertificates as $trustedCertificate) {
            if ($this->validateChain($untrustedCertificates, $trustedCertificate)) {
                return;
            }
        }

        throw new RuntimeException('Unable to validate the certificate chain.');
    }

    /**
     * @param string[] $untrustedCertificates
     */
    public function validateChain(array $untrustedCertificates, string $trustedCertificate): bool
    {
        $untrustedCertificates = array_map(
            static fn (string $cert): Certificate => Certificate::fromPEM(PEM::fromString($cert)),
            array_reverse($untrustedCertificates)
        );
        $trustedCertificate = Certificate::fromPEM(PEM::fromString($trustedCertificate));

        // The trust path and the authenticator certificate are the same
        if (count(
            $untrustedCertificates
        ) === 1 && $untrustedCertificates[0]->toPEM()->string() === $trustedCertificate->toPEM()->string()) {
            return true;
        }
        $uniqueCertificates = array_map(
            static fn (Certificate $cert): string => $cert->toPEM()
                ->string(),
            array_merge($untrustedCertificates, [$trustedCertificate])
        );
        count(array_unique($uniqueCertificates)) === count($uniqueCertificates) || throw new InvalidArgumentException(
            'Invalid certificate chain with duplicated certificates.'
        );

        if (! $this->validateCertificates($trustedCertificate, ...$untrustedCertificates)) {
            return false;
        }

        $certificates = array_merge([$trustedCertificate], $untrustedCertificates);
        $numCerts = count($certificates);
        for ($i = 1; $i < $numCerts; $i++) {
            if ($this->isRevoked($certificates[$i])) {
                throw new RuntimeException('Unable to validate the certificate chain. Revoked certificate found.');
            }
        }

        return true;
    }

    public function isRevoked(Certificate $subject): bool
    {
        try {
            $csn = $subject->tbsCertificate()
                ->serialNumber();
        } catch (Throwable $e) {
            throw new InvalidArgumentException(sprintf('Failed to parse certificate: %s', $e->getMessage()), 0, $e);
        }

        try {
            $urls = $this->getCrlUrlList($subject);
        } catch (InvalidArgumentException $e) {
            if ($this->allowFailures) {
                return false;
            }
            throw new InvalidArgumentException('Failed to get CRL distribution points: ' . $e->getMessage(), 0, $e);
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
                throw new InvalidArgumentException(sprintf(
                    'Failed to retrieve CRL %s:' . PHP_EOL . '%s',
                    $url,
                    $e->getMessage()
                ), 0, $e);
            }
        }
        return false;
    }

    private function validateCertificates(Certificate ...$certificates): bool
    {
        try {
            $config = PathValidationConfig::create($this->clock->now(), self::MAX_VALIDATION_LENGTH);
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
            $request = $this->requestFactory->createRequest('GET', $url);
            $response = $this->client->sendRequest($request);
            if ($response->getStatusCode() !== 200) {
                throw new InvalidArgumentException(sprintf('Failed to download CRL for certificate from %s', $url));
            }
            $crlData = $response->getBody()
                ->getContents();
            $crl = UnspecifiedType::fromDER($crlData)->asSequence();
            count($crl) === 3 || throw new InvalidArgumentException('Invalid CRL.');
            $tbsCertList = $crl->at(0)
                ->asSequence();
            count($tbsCertList) >= 6 || throw new InvalidArgumentException('Invalid CRL.');
            $list = $tbsCertList->at(5)
                ->asSequence();

            return array_map(static function (UnspecifiedType $r): string {
                $sequence = $r->asSequence();
                count($sequence) >= 1 || throw new InvalidArgumentException('Invalid CRL.');
                return $sequence->at(0)
                    ->asInteger()
                    ->number();
            }, $list->elements());
        } catch (Throwable $e) {
            throw new InvalidArgumentException(sprintf(
                'Failed to download CRL for certificate from %s',
                $url
            ), 0, $e);
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
            throw new InvalidArgumentException(
                'Failed to get CRL distribution points from certificate: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }
}
