<?php

declare(strict_types=1);

namespace App\SpcDemo;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use Symfony\Component\Serializer\Serializer;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticationExtensions\PaymentExtensionOutputChecker;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\ClientDataCollector\ClientDataCollectorManager;
use Webauthn\ClientDataCollector\PaymentClientDataCollector;
use Webauthn\ClientDataCollector\WebauthnAuthenticationCollector;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

$autoload = __DIR__ . '/../vendor/autoload.php';
if (! is_file($autoload)) {
    fwrite(\STDERR, "Run `composer install` in docs/examples/spc-demo/ first.\n");
    exit(1);
}
require_once $autoload;

/**
 * Wires everything the SPC demo needs:
 *
 *  - The Webauthn serializer (loads every denormalizer the lib ships with,
 *    including the SPC ones for `payment`, `total`, `instrument`, …).
 *  - A `CeremonyStepManagerFactory` configured with a
 *    `ClientDataCollectorManager` that handles BOTH `webauthn.get` /
 *    `webauthn.create` (standard WebAuthn) and `payment.get` (SPC).
 *  - Validators for registration (attestation) and authentication
 *    (assertion).
 *  - A trivial JSON-file storage for credentials so the demo runs
 *    out-of-the-box with `php -S`.
 */
final class Container
{
    public string $relyingPartyId;
    public string $relyingPartyName;
    /** @var string[] */
    public array $allowedOrigins;

    public AttestationStatementSupportManager $attestationManager;
    public Manager $algorithmManager;
    public CeremonyStepManagerFactory $ceremonyFactory;
    public AuthenticatorAttestationResponseValidator $attestationValidator;
    public AuthenticatorAssertionResponseValidator $assertionValidator;
    public Serializer $serializer;
    public CredentialStore $credentialStore;
    public ChallengeStore $challengeStore;

    public function __construct()
    {
        $this->relyingPartyId = $_ENV['RP_ID'] ?? 'localhost';
        $this->relyingPartyName = 'SPC Demo Bank';
        $this->allowedOrigins = explode(',', $_ENV['ALLOWED_ORIGINS'] ?? 'http://localhost:8000,http://localhost:8001');

        $this->attestationManager = new AttestationStatementSupportManager();
        $this->attestationManager->add(new NoneAttestationStatementSupport());

        $this->algorithmManager = Manager::create()->add(ES256::create(), RS256::create());

        $serializer = (new WebauthnSerializerFactory($this->attestationManager))->create();
        \assert($serializer instanceof Serializer);
        $this->serializer = $serializer;

        $clientDataManager = new ClientDataCollectorManager([
            new WebauthnAuthenticationCollector(),
            new PaymentClientDataCollector($this->serializer),
        ]);

        $extensionHandler = ExtensionOutputCheckerHandler::create();
        $extensionHandler->add(new PaymentExtensionOutputChecker());

        $this->ceremonyFactory = new CeremonyStepManagerFactory();
        $this->ceremonyFactory->setAttestationStatementSupportManager($this->attestationManager);
        $this->ceremonyFactory->setAlgorithmManager($this->algorithmManager);
        $this->ceremonyFactory->setExtensionOutputCheckerHandler($extensionHandler);
        $this->ceremonyFactory->setClientDataCollectorManager($clientDataManager);
        $this->ceremonyFactory->setAllowedOrigins($this->allowedOrigins);

        $this->attestationValidator = AuthenticatorAttestationResponseValidator::create(
            ceremonyStepManager: $this->ceremonyFactory->creationCeremony(),
        );
        $this->assertionValidator = AuthenticatorAssertionResponseValidator::create(
            ceremonyStepManager: $this->ceremonyFactory->requestCeremony(),
        );

        $varDir = $_ENV['VAR_DIR'] ?? __DIR__ . '/../var';
        $this->credentialStore = new CredentialStore($varDir . '/credentials.json', $this->serializer);
        $this->challengeStore = new ChallengeStore($varDir . '/challenges.json');
    }
}
