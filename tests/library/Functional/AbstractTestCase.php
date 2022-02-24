<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Http\Mock\Client;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Symfony\Component\Finder\Finder;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CertificateChainChecker\CertificateChainChecker;
use Webauthn\CertificateChainChecker\OpenSSLCertificateChainChecker;
use Webauthn\MetadataService\MetadataService;
use Webauthn\MetadataService\MetadataStatementRepository as MetadataStatementRepositoryInterface;
use Webauthn\MetadataService\SingleMetadata;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\Tests\MockedMappedResponseTrait;
use Webauthn\Tests\MockedPublicKeyCredentialSourceTrait;
use Webauthn\Tests\MockedRequestTrait;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

abstract class AbstractTestCase extends TestCase
{
    use MockedRequestTrait;
    use MockedPublicKeyCredentialSourceTrait;
    use MockedMappedResponseTrait;

    private ?PublicKeyCredentialLoader $publicKeyCredentialLoader = null;

    private ?AuthenticatorAttestationResponseValidator $authenticatorAttestationResponseValidator = null;

    private ?AuthenticatorAssertionResponseValidator $authenticatorAssertionResponseValidator = null;

    private ?Manager $algorithmManager = null;

    private ?AttestationObjectLoader $attestationObjectLoader = null;

    private ?\Webauthn\Tests\Functional\MetadataStatementRepository $metadataStatementRepository = null;

    private ?OpenSSLCertificateChainChecker $certificateChainChecker = null;

    protected function getPublicKeyCredentialLoader(): PublicKeyCredentialLoader
    {
        if ($this->publicKeyCredentialLoader === null) {
            $this->publicKeyCredentialLoader = new PublicKeyCredentialLoader($this->getAttestationObjectLoader());
        }

        return $this->publicKeyCredentialLoader;
    }

    protected function getAuthenticatorAttestationResponseValidator(
        PublicKeyCredentialSourceRepository $credentialRepository,
        ?ClientInterface $client = null
    ): AuthenticatorAttestationResponseValidator {
        if ($this->authenticatorAttestationResponseValidator === null) {
            $this->authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
                $this->getAttestationStatementSupportManager($client),
                $credentialRepository,
                new IgnoreTokenBindingHandler(),
                new ExtensionOutputCheckerHandler()
            );
            $this->authenticatorAttestationResponseValidator->setCertificateChainChecker(
                $this->getCertificateChainChecker()
            );
            $this->authenticatorAttestationResponseValidator->setMetadataStatementRepository(
                $this->getMetadataStatementRepository($client)
            );
        }

        return $this->authenticatorAttestationResponseValidator;
    }

    protected function getAuthenticatorAssertionResponseValidator(
        PublicKeyCredentialSourceRepository $credentialRepository
    ): AuthenticatorAssertionResponseValidator {
        if ($this->authenticatorAssertionResponseValidator === null) {
            $this->authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
                $credentialRepository,
                new TokenBindingNotSupportedHandler(),
                new ExtensionOutputCheckerHandler(),
                $this->getAlgorithmManager()
            );
        }

        return $this->authenticatorAssertionResponseValidator;
    }

    protected function getResponsesMap(): array
    {
        return [
            'http://mds.fidoalliance.org/CA-1.crl' => '-----BEGIN X509 CRL-----
MIIBDTCBswIBATAKBggqhkjOPQQDAjBTMQswCQYDVQQGEwJVUzEWMBQGA1UEChMN
RklETyBBbGxpYW5jZTEdMBsGA1UECxMUTWV0YWRhdGEgVE9DIFNpZ25pbmcxDTAL
BgNVBAMTBENBLTEXDTIwMTEwNzAwMDAwMFoXDTIwMTIxNTAwMDAwMFqgLzAtMAoG
A1UdFAQDAgFBMB8GA1UdIwQYMBaAFGkRXi1pZIWdlrjW/1zNvzx1z0wYMAoGCCqG
SM49BAMCA0kAMEYCIQD4xhMWP+ghBvRA4YwJ4jmr4sUoBFnz+5ffj9SDNMPrbgIh
AIYHVu95YrQwqv4uIW+Gstc+QU2NH/1isNZZDKCoTm7g
-----END X509 CRL-----',
            'http://mds.fidoalliance.org/Root.crl' => '-----BEGIN X509 CRL-----
MIIBLDCBswIBATAKBggqhkjOPQQDAzBTMQswCQYDVQQGEwJVUzEWMBQGA1UEChMN
RklETyBBbGxpYW5jZTEdMBsGA1UECxMUTWV0YWRhdGEgVE9DIFNpZ25pbmcxDTAL
BgNVBAMTBFJvb3QXDTIwMTAwNzAwMDAwMFoXDTIxMDExNTAwMDAwMFqgLzAtMAoG
A1UdFAQDAgEWMB8GA1UdIwQYMBaAFNKlHwun9mLIQNTYvbnXjtFUu7xGMAoGCCqG
SM49BAMDA2gAMGUCMQD01xgfR4/+HKha6PcEQDSziv2ygxybZHs4Oy/BICNwPMAH
Ae85o0gdiH4Ottsbry0CMCGnRSe8/qWGrmr8dsXdxf5OzPHMXfAzRVkK18bUclml
umyNfT+4yHMEylqLY1ENjQ==
-----END X509 CRL-----',
            'https://mds.certinfra.fidoalliance.org/crl/MDSCA-1.crl' => '-----BEGIN X509 CRL-----
MIIB5DCCAYoCAQEwCgYIKoZIzj0EAwIwZzELMAkGA1UEBhMCVVMxFjAUBgNVBAoM
DUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRhdGEgVE9DIFNpZ25p
bmcgRkFLRTEXMBUGA1UEAwwORkFLRSBDQS0xIEZBS0UXDTE4MDIwMTAwMDAwMFoX
DTIyMDIwMTAwMDAwMFowgcAwLgIPBPk2GqWZsKrpJc7cvyH5Fw0xNjA0MTMwMDAw
MDBaMAwwCgYDVR0VBAMKAQAwLgIPBDkEQCT6dkHZbQeTR0PRFw0xNzAzMjUwMDAw
MDBaMAwwCgYDVR0VBAMKAQAwLgIPBGfBlD+8Ie+24rwUa9GgFw0xNjAzMDEwMDAw
MDBaMAwwCgYDVR0VBAMKAQAwLgIPBIBnSd4we71RdaJtc/XzFw0xODAzMjUwMDAw
MDBaMAwwCgYDVR0VBAMKAQCgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFFBa
Ubxo9hKU9MSPAXOyAdzujD8yMAoGCCqGSM49BAMCA0gAMEUCIQC1QuSZH6NzquOz
w3or2SluYJFt30FLgLlLk4nsRT7bGAIgX1rOA6vFWka4Dz1ywPowiJk5UJQBbLrr
WYUVTEP++J8=
-----END X509 CRL-----',
            'https://mds.certinfra.fidoalliance.org/crl/MDSROOT.crl' => '-----BEGIN X509 CRL-----
MIIB1jCCAV0CAQEwCgYIKoZIzj0EAwMwZzELMAkGA1UEBhMCVVMxFjAUBgNVBAoM
DUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRhdGEgVE9DIFNpZ25p
bmcgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UXDTIwMDIwMTAwMDAwMFoX
DTIyMDIwMTAwMDAwMFowgZMwLwIQBCZYfWbvAtCiCiDkzlVBNhcNMTQwMzAxMDAw
MDAwWjAMMAoGA1UdFQQDCgEAMC8CEHAc4zP0TEonwYAmqsFKK0oXDTE0MDQxMzAw
MDAwMFowDDAKBgNVHRUEAwoBADAvAhD7GIBl71xpqmIqTSJH2pXBFw0xNTAzMjUw
MDAwMDBaMAwwCgYDVR0VBAMKAQCgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaA
FN33msgc7+Ff06Hr2zNfMPRqGZlZMAoGCCqGSM49BAMDA2cAMGQCMBYPltbCN54u
A5eG2BqhHXfIrp7DLgxJYWaXF7lIk/e5yFpYqJDksq0ZGIyK+CGS8QIwXIbqlrb0
8lFFz+Onh5B1JminysL+Yjfg8ogovLJg+ANU0aRPtqh5iOzV7FB0tU+Z
-----END X509 CRL-----',
        ];
    }

    private function getAttestationStatementSupportManager(?ClientInterface $client): AttestationStatementSupportManager
    {
        if ($client === null) {
            $client = new Client();
            $this->prepareResponsesMap($client);
        }
        $attestationStatementSupportManager = new AttestationStatementSupportManager();
        $attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
        $attestationStatementSupportManager->add(new AppleAttestationStatementSupport());
        $attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport());
        $androidSafetyNetAttestationStatementSupport = new AndroidSafetyNetAttestationStatementSupport();
        $androidSafetyNetAttestationStatementSupport
            ->enableApiVerification($client, 'api_key', new Psr17Factory())
            ->setLeeway(0)
            ->setMaxAge(99999999999)
            ;
        $attestationStatementSupportManager->add($androidSafetyNetAttestationStatementSupport);
        $attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport());
        $attestationStatementSupportManager->add(new PackedAttestationStatementSupport(
            $this->getAlgorithmManager()
        ));
        $attestationStatementSupportManager->add(new TPMAttestationStatementSupport());

        return $attestationStatementSupportManager;
    }

    private function getAlgorithmManager(): Manager
    {
        if ($this->algorithmManager === null) {
            $this->algorithmManager = new Manager();
            $this->algorithmManager->add(new ES256());
            $this->algorithmManager->add(new ES384());
            $this->algorithmManager->add(new ES512());
            $this->algorithmManager->add(new RS1());
            $this->algorithmManager->add(new RS256());
            $this->algorithmManager->add(new RS384());
            $this->algorithmManager->add(new RS512());
            $this->algorithmManager->add(new EdDSA());
        }

        return $this->algorithmManager;
    }

    private function getAttestationObjectLoader(): AttestationObjectLoader
    {
        if ($this->attestationObjectLoader === null) {
            $this->attestationObjectLoader = new AttestationObjectLoader(
                $this->getAttestationStatementSupportManager(null)
            );
        }

        return $this->attestationObjectLoader;
    }

    private function getMetadataStatementRepository(?ClientInterface $client): MetadataStatementRepositoryInterface
    {
        if ($client === null) {
            $client = new Client();
            $this->prepareResponsesMap($client);
        }
        if ($this->metadataStatementRepository === null) {
            $this->metadataStatementRepository = new MetadataStatementRepository();
            foreach ($this->getSingleStatements() as $statement) {
                $this->metadataStatementRepository->addSingleStatement(new SingleMetadata($statement, false));
            }

            /*$this->metadataStatementRepository->addService(
                new MetadataService(
                    'https://mds.certinfra.fidoalliance.org/execute/0fdcfc99b393efd496c165ee387e1f3949c3a16f85cfb0aa9c02bca979e75bdb',
                    $client,
                    new Psr17Factory()
                )
            );
            $this->metadataStatementRepository->addService(
                new MetadataService(
                    'https://mds.certinfra.fidoalliance.org/execute/4926abdc35e558244ceaea24a384dee5cc5bf97fb7fec060f184be4fed07d82e',
                    $client,
                    new Psr17Factory()
                )
            );
            $this->metadataStatementRepository->addService(
                new MetadataService(
                    'https://mds.certinfra.fidoalliance.org/execute/ba5a161e75d267f70c00c2546234dcb271a3b8e5c189e5b978e9e1c4ccc8f7a4',
                    $client,
                    new Psr17Factory()
                )
            );
            $this->metadataStatementRepository->addService(
                new MetadataService(
                    'https://mds.certinfra.fidoalliance.org/execute/bd578e0ef8b075efa44400616e976a47aa56292d2e07c446d854e826b7451022',
                    $client,
                    new Psr17Factory()
                )
            );
            $this->metadataStatementRepository->addService(
                new MetadataService(
                    'https://mds.certinfra.fidoalliance.org/execute/cccf981a98027d2bef4376e5a8fca839db552f35dd1e87e874c32e04d8c95e81',
                    $client,
                    new Psr17Factory()
                )
            );*/
        }

        return $this->metadataStatementRepository;
    }

    private function getSingleStatements(): iterable
    {
        $finder = new Finder();
        $finder->files()
            ->in(__DIR__ . '/../../metadataStatements')
        ;

        foreach ($finder->files()->name('*.json') as $file) {
            yield file_get_contents($file->getRealPath());
        }
    }

    private function getCertificateChainChecker(): CertificateChainChecker
    {
        if ($this->certificateChainChecker === null) {
            $psr18Client = new Client();
            $this->prepareResponsesMap($psr18Client);

            $psr17Factory = new Psr17Factory();
            $this->certificateChainChecker = new OpenSSLCertificateChainChecker($psr18Client, $psr17Factory);
        }

        return $this->certificateChainChecker;
    }
}
