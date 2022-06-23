<?php

declare(strict_types=1);

namespace Webauthn\CertificateChainChecker;

use Assert\Assertion;
use function count;
use FG\ASN1\ASNObject;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\Sequence;
use const FILE_APPEND;
use function in_array;
use function is_int;
use const PHP_EOL;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use function Safe\file_put_contents;
use function Safe\rename;
use function Safe\tempnam;
use function Safe\unlink;
use Throwable;
use Webauthn\CertificateToolbox;
use const X509_PURPOSE_ANY;

final class PhpCertificateChainChecker implements CertificateChainChecker
{
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory
    ) {
    }

    /**
     * @param string[] $authenticatorCertificates
     * @param string[] $trustedCertificates
     */
    public function check(array $authenticatorCertificates, array $trustedCertificates): void
    {
        if (count($trustedCertificates) === 0) {
            $this->checkCertificatesValidity($authenticatorCertificates, true);

            return;
        }
        $this->checkCertificatesValidity($authenticatorCertificates, false);

        $trustedCertificatesFilenames = [];
        foreach ($trustedCertificates as $trustedCertificate) {
            $trustedCertificatesFilenames[] = $this->saveToTemporaryFile(
                $trustedCertificate,
                'webauthn-trusted-',
                '.pem'
            );
        }

        $leafCertificate = array_shift($authenticatorCertificates);
        Assertion::notNull($leafCertificate, 'No leaf certificate from the authenticator certificate list.');
        $untrustedCertificatesFilename = null;
        if (count($authenticatorCertificates) !== 0) {
            $untrustedCertificatesFilename = $this->saveToTemporaryFile(
                implode(PHP_EOL, $authenticatorCertificates),
                'webauthn-untrusted-',
                '.pem'
            );
        }

        $result = openssl_x509_checkpurpose(
            $leafCertificate,
            X509_PURPOSE_ANY,
            $trustedCertificatesFilenames,
            $untrustedCertificatesFilename
        );
        if ($result === false) {
            throw new RuntimeException('Unable to verify the certificate chain');
        }
        $crls = [];
        foreach ($trustedCertificates as $certificate) {
            $crl = $this->getCrls($certificate);
            if ($crl !== '') {
                $crls[] = $crl;
            }
        }
        foreach ($authenticatorCertificates as $certificate) {
            $crl = $this->getCrls($certificate);
            if ($crl !== '') {
                $crls[] = $crl;
            }
        }
        $revokedCertificates = [];
        foreach ($crls as $crl) {
            $crl = CertificateToolbox::convertPEMToDER($crl);
            $asn = ASNObject::fromBinary($crl);
            Assertion::isInstanceOf($asn, Sequence::class, 'Invalid CRL(1)');
            $asn = $asn->getFirstChild();
            Assertion::isInstanceOf($asn, Sequence::class, 'Invalid CRL(2)');
            Assertion::minCount($asn->getChildren(), 5);
            $list = $asn->getChildren()[5];
            Assertion::isInstanceOf($list, Sequence::class, 'Invalid CRL(3)');
            Assertion::allIsInstanceOf($list->getChildren(), Sequence::class, 'Invalid CRL(3)');
            $revokedCertificates = array_merge($revokedCertificates, array_map(static function (Sequence $r): string {
                $sn = $r->getFirstChild();
                Assertion::isInstanceOf($sn, Integer::class, 'Invalid CRL(4)');

                return $sn->getContent();
            }, $list->getChildren()));
        }
        $certificatesIds = $this->getCertificatesIds(...$trustedCertificates, ...$authenticatorCertificates);
        foreach ($certificatesIds as $certificatesId) {
            if (in_array($certificatesId, $revokedCertificates, true)) {
                throw new RuntimeException(sprintf(
                    'The certificate with the serial number "%s" is revoked',
                    $certificatesId
                ));
            }
        }

        foreach ($trustedCertificatesFilenames as $filename) {
            unlink($filename);
        }
        if ($untrustedCertificatesFilename !== null) {
            unlink($untrustedCertificatesFilename);
        }
    }

    /**
     * @param string[] $certificates
     */
    private function checkCertificatesValidity(array $certificates, bool $allowRootCertificate): void
    {
        foreach ($certificates as $certificate) {
            $parsed = openssl_x509_parse($certificate);
            Assertion::isArray($parsed, 'Unable to read the certificate. Submitted data was: ' . $certificate);
            if ($allowRootCertificate === false) {
                $this->checkRootCertificate($parsed);
            }

            Assertion::keyExists($parsed, 'validTo_time_t', 'The certificate has no validity period');
            Assertion::keyExists($parsed, 'validFrom_time_t', 'The certificate has no validity period');
            Assertion::lessOrEqualThan(time(), $parsed['validTo_time_t'], 'The certificate expired');
            Assertion::greaterOrEqualThan(time(), $parsed['validFrom_time_t'], 'The certificate is not usable yet');
        }
    }

    /**
     * @param array<string, mixed> $parsed
     */
    private function checkRootCertificate(array $parsed): void
    {
        Assertion::keyExists($parsed, 'subject', 'The certificate has no subject');
        Assertion::keyExists($parsed, 'issuer', 'The certificate has no issuer');
        $subject = $parsed['subject'];
        $issuer = $parsed['issuer'];
        ksort($subject);
        ksort($issuer);
        Assertion::notEq($subject, $issuer, 'Root certificates are not allowed');
    }

    private function saveToTemporaryFile(string $certificate, string $prefix, string $suffix): string
    {
        $filename = tempnam(sys_get_temp_dir(), $prefix);
        rename($filename, $filename . $suffix);
        file_put_contents($filename . $suffix, $certificate, FILE_APPEND);

        return $filename . $suffix;
    }

    private function getCrls(string $certificate): string
    {
        $parsed = openssl_x509_parse($certificate);
        if ($parsed === false || ! isset($parsed['extensions']['crlDistributionPoints'])) {
            return '';
        }
        $endpoint = $parsed['extensions']['crlDistributionPoints'];
        $pos = mb_strpos((string) $endpoint, 'URI:');
        if (! is_int($pos)) {
            return '';
        }
        $endpoint = trim(mb_substr((string) $endpoint, $pos + 4));

        $request = $this->requestFactory->createRequest('GET', $endpoint);
        try {
            $response = $this->client->sendRequest($request);
            if ($response->getStatusCode() !== 200) {
                return '';
            }

            return $response->getBody()
                ->getContents()
                ;
        } catch (Throwable) {
            return '';
        }
    }

    /**
     * @return string[]
     */
    private function getCertificatesIds(string ...$certificates): iterable
    {
        return array_map(static function (string $cert): string {
            $details = openssl_x509_parse($cert);
            Assertion::isArray($details, 'Unable to parse the X509 certificate');

            return $details['serialNumber'];
        }, $certificates);
    }
}
