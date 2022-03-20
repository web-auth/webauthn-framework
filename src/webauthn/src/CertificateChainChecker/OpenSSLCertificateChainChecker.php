<?php

declare(strict_types=1);

namespace Webauthn\CertificateChainChecker;

use Assert\Assertion;
use function count;
use const FILE_APPEND;
use InvalidArgumentException;
use function is_int;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use Symfony\Component\Process\Process;

final class OpenSSLCertificateChainChecker implements CertificateChainChecker
{
    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requestFactory
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

        $hasCrls = false;
        $processArguments = ['-no-CAfile', '-no-CApath'];

        $caDirname = $this->createTemporaryDirectory();
        $processArguments[] = '--CApath';
        $processArguments[] = $caDirname;

        foreach ($trustedCertificates as $certificate) {
            $this->saveToTemporaryFile($caDirname, $certificate, 'webauthn-trusted-', '.pem');
            $crl = $this->getCrls($certificate);
            if ($crl !== '') {
                $hasCrls = true;
                $this->saveToTemporaryFile($caDirname, $crl, 'webauthn-trusted-crl-', '.crl');
            }
        }

        $rehashProcess = new Process(['openssl', 'rehash', $caDirname]);
        $rehashProcess->run();
        while ($rehashProcess->isRunning()) {
            //Just wait
        }
        if (! $rehashProcess->isSuccessful()) {
            throw new InvalidArgumentException('Invalid certificate or certificate chain');
        }

        $filenames = [];
        $leafCertificate = array_shift($authenticatorCertificates);
        $leafFilename = $this->saveToTemporaryFile(sys_get_temp_dir(), $leafCertificate, 'webauthn-leaf-', '.pem');
        $crl = $this->getCrls($leafCertificate);
        if ($crl !== '') {
            $hasCrls = true;
            $this->saveToTemporaryFile($caDirname, $crl, 'webauthn-leaf-crl-', '.pem');
        }
        $filenames[] = $leafFilename;

        foreach ($authenticatorCertificates as $certificate) {
            $untrustedFilename = $this->saveToTemporaryFile(
                sys_get_temp_dir(),
                $certificate,
                'webauthn-untrusted-',
                '.pem'
            );
            $crl = $this->getCrls($certificate);
            if ($crl !== '') {
                $hasCrls = true;
                $this->saveToTemporaryFile($caDirname, $crl, 'webauthn-untrusted-crl-', '.pem');
            }
            $processArguments[] = '-untrusted';
            $processArguments[] = $untrustedFilename;
            $filenames[] = $untrustedFilename;
        }

        $processArguments[] = $leafFilename;
        if ($hasCrls) {
            array_unshift($processArguments, '-crl_check');
            array_unshift($processArguments, '-crl_check_all');
            //array_unshift($processArguments, '-crl_download');
            array_unshift($processArguments, '-extended_crl');
        }
        array_unshift($processArguments, 'openssl', 'verify');

        $process = new Process($processArguments);
        $process->run();
        while ($process->isRunning()) {
            //Just wait
        }

        foreach ($filenames as $filename) {
            unlink($filename);
        }
        $this->deleteDirectory($caDirname);

        if (! $process->isSuccessful()) {
            throw new InvalidArgumentException('Invalid certificate or certificate chain');
        }
    }

    /**
     * @param string[] $certificates
     */
    private function checkCertificatesValidity(array $certificates, bool $allowRootCertificate): void
    {
        foreach ($certificates as $certificate) {
            $parsed = openssl_x509_parse($certificate);
            Assertion::isArray($parsed, 'Unable to read the certificate');
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

    private function createTemporaryDirectory(): string
    {
        $caDir = tempnam(sys_get_temp_dir(), 'webauthn-ca-');
        Assertion::string($caDir, 'Unable to create a temporary folder');
        if (file_exists($caDir)) {
            unlink($caDir);
        }
        if (! mkdir($caDir) && ! is_dir($caDir)) {
            throw new RuntimeException(sprintf('Directory "%s" was not created', $caDir));
        }
        if (! is_dir($caDir)) {
            throw new RuntimeException(sprintf('Directory "%s" was not created', $caDir));
        }

        return $caDir;
    }

    private function deleteDirectory(string $dirname): void
    {
        $rehashProcess = new Process(['rm', '-rf', $dirname]);
        $rehashProcess->run();
        while ($rehashProcess->isRunning()) {
            //Just wait
        }
    }

    private function saveToTemporaryFile(string $folder, string $certificate, string $prefix, string $suffix): string
    {
        $filename = tempnam($folder, $prefix);
        Assertion::string($filename, 'Unable to create a temporary folder');
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
        $pos = mb_strpos($endpoint, 'URI:');
        if (! is_int($pos)) {
            return '';
        }

        $endpoint = trim(mb_substr($endpoint, $pos + 4));
        $request = $this->requestFactory->createRequest('GET', $endpoint);
        $response = $this->client->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            return '';
        }

        return $response->getBody()
            ->getContents()
        ;
    }
}
