<?php

declare(strict_types=1);

namespace App\PrfDemo;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use Symfony\Component\Serializer\Serializer;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

// Two ways to load the lib:
//   1. Standalone — `composer install` in this directory pulls
//      web-auth/webauthn-lib >= 5.4 into ./vendor.
//   2. Inside the monorepo — fall back to the framework's own
//      vendor/autoload.php which exposes the lib via PSR-4.
$autoloads = [
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/../../../../vendor/autoload.php',
];
$loaded = false;
foreach ($autoloads as $autoload) {
    if (is_file($autoload)) {
        require_once $autoload;
        $loaded = true;
        break;
    }
}
if (! $loaded) {
    fwrite(\STDERR, "Run `composer install` in docs/examples/prf-demo/ first.\n");
    exit(1);
}

/**
 * Wires the minimum the PRF demo needs: serializer, attestation/assertion validators,
 * and a JSON-file credential + ciphertext store.
 *
 * Note: the framework does not validate `clientExtensionResults.prf.results` server-side
 * (and should not — the PRF output is a secret that lives in the browser only). We just
 * have to surface the PRF inputs in the options sent to the browser; the rest is Web Crypto
 * inside the page.
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

    public function __construct()
    {
        $this->relyingPartyId = $_ENV['RP_ID'] ?? 'localhost';
        $this->relyingPartyName = 'PRF Demo Vault';
        $this->allowedOrigins = explode(',', $_ENV['ALLOWED_ORIGINS'] ?? 'http://localhost:8000');

        $this->attestationManager = new AttestationStatementSupportManager();
        $this->attestationManager->add(new NoneAttestationStatementSupport());

        $this->algorithmManager = Manager::create()->add(ES256::create(), RS256::create());

        $serializer = (new WebauthnSerializerFactory($this->attestationManager))->create();
        \assert($serializer instanceof Serializer);
        $this->serializer = $serializer;

        $this->ceremonyFactory = new CeremonyStepManagerFactory();
        $this->ceremonyFactory->setAttestationStatementSupportManager($this->attestationManager);
        $this->ceremonyFactory->setAlgorithmManager($this->algorithmManager);
        $this->ceremonyFactory->setAllowedOrigins($this->allowedOrigins);

        $this->attestationValidator = AuthenticatorAttestationResponseValidator::create(
            ceremonyStepManager: $this->ceremonyFactory->creationCeremony(),
        );
        $this->assertionValidator = AuthenticatorAssertionResponseValidator::create(
            ceremonyStepManager: $this->ceremonyFactory->requestCeremony(),
        );

        $varDir = $_ENV['VAR_DIR'] ?? __DIR__ . '/../var';
        $this->credentialStore = new CredentialStore($varDir . '/credentials.json', $this->serializer);
    }
}
