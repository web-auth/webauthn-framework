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
use Nyholm\Psr7\Response;
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
use Webauthn\CertificateChainChecker\PhpCertificateChainChecker;
use Webauthn\MetadataService\MetadataStatementRepository as MetadataStatementRepositoryInterface;
use Webauthn\MetadataService\Service\ChainedMetadataServices;
use Webauthn\MetadataService\Service\FidoAllianceCompliantMetadataService;
use Webauthn\MetadataService\Service\LocalResourceMetadataService;
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

    private ?MetadataStatementRepository $metadataStatementRepository = null;

    private ?PhpCertificateChainChecker $certificateChainChecker = null;

    private ?StatusReportRepository $statusReportRepository = null;

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
            $this->authenticatorAttestationResponseValidator->enableMetadataStatementSupport(
                $this->getMetadataStatementRepository($client),
                $this->getStatusReportRepository(),
                $this->getCertificateChainChecker(),
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
        $urls = [
            'https://mds3.certinfra.fidoalliance.org/pki/MDS3ROOT.crt' => file_get_contents(
                __DIR__ . '/../../certificates/MDS3ROOT.crt'
            ),
            'https://mds3.certinfra.fidoalliance.org/crl/MDSCA-1.crl' => file_get_contents(
                __DIR__ . '/../../certificates/MDSCA-1.crl'
            ),
            'https://mds3.certinfra.fidoalliance.org/crl/MDSROOT.crl' => file_get_contents(
                __DIR__ . '/../../certificates/MDSROOT.crl'
            ),
        ];

        $finder = new Finder();
        $finder->files()
            ->in(__DIR__ . '/../../metadataServices')
        ;

        foreach ($finder->files() as $file) {
            $urls[sprintf(
                'https://mds3.certinfra.fidoalliance.org/execute/%s',
                $file->getRelativePathname()
            )] = file_get_contents($file->getRealPath());
        }

        return $urls;
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
            ->setMaxAge(99_999_999_999)
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
            $metadataService = new ChainedMetadataServices();
            foreach ($this->getSingleStatements() as $filename) {
                $metadataService->addServices(LocalResourceMetadataService::create($filename));
            }
            foreach ($this->getDistantStatements() as $filename) {
                $response = new Response(200, [], file_get_contents($filename));
                $client = new Client();
                $client->addResponse($response);

                $metadataService->addServices(
                    FidoAllianceCompliantMetadataService::create(
                        new Psr17Factory(),
                        $client,
                        'https://foo.bar/data'
                    )
                );
            }

            $response = new Response(200, [], file_get_contents(__DIR__ . '/../../blob.jwt'));
            $client = new Client();
            $client->addResponse($response);
            $metadataService->addServices(
                FidoAllianceCompliantMetadataService::create(new Psr17Factory(), $client, 'https://foo.bar/data')
            );

            $this->metadataStatementRepository = new MetadataStatementRepository($metadataService);
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
            yield $file->getRealPath();
        }
    }

    private function getDistantStatements(): iterable
    {
        $finder = new Finder();
        $finder->files()
            ->in(__DIR__ . '/../../metadataServices')
        ;

        foreach ($finder->files() as $file) {
            yield $file->getRealPath();
        }
    }

    private function getCertificateChainChecker(): CertificateChainChecker
    {
        if ($this->certificateChainChecker === null) {
            $psr18Client = new Client();
            $this->prepareResponsesMap($psr18Client);

            $psr17Factory = new Psr17Factory();
            $this->certificateChainChecker = new PhpCertificateChainChecker($psr18Client, $psr17Factory);
        }

        return $this->certificateChainChecker;
    }

    private function getStatusReportRepository(): StatusReportRepository
    {
        if ($this->statusReportRepository === null) {
            $this->statusReportRepository = new StatusReportRepository();
        }

        return $this->statusReportRepository;
    }
}
