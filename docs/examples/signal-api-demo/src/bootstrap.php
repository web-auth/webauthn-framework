<?php

declare(strict_types=1);

namespace App\SignalApiDemo;

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

$autoload = __DIR__ . '/../vendor/autoload.php';
if (! is_file($autoload)) {
    fwrite(\STDERR, "Run `composer install` in docs/examples/signal-api-demo/ first.\n");
    exit(1);
}
require_once $autoload;

require_once __DIR__ . '/UserStore.php';
require_once __DIR__ . '/CredentialStore.php';

/**
 * Minimal service container for the demo.
 *
 * Wires together the four things a pure-PHP relying party needs to run a
 * WebAuthn ceremony:
 *
 *  - A serializer that knows how to (de)serialize the WebAuthn options
 *    objects sent to the browser and the PublicKeyCredential JSON the
 *    browser sends back.
 *  - An attestation statement support manager. The demo accepts the `none`
 *    format only, which is the default for platform authenticators and the
 *    safe choice for a passwordless login that does not need attestation.
 *  - A COSE algorithm manager. ES256 and RS256 cover every authenticator
 *    in circulation, including platform and roaming.
 *  - Two validators wired on top of a CeremonyStepManager configured with
 *    the relying party's allowed origins.
 *
 * Persistence is delegated to two demo-only JSON-file stores
 * (UserStore + CredentialStore). Production code MUST replace them with a
 * real database behind the framework's repository interfaces.
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

    public UserStore $userStore;

    public CredentialStore $credentialStore;

    public function __construct()
    {
        $this->relyingPartyId = $_ENV['RP_ID'] ?? 'localhost';
        $this->relyingPartyName = 'WebAuthn Signal API Demo';
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
            $this->ceremonyFactory->creationCeremony(),
        );
        $this->assertionValidator = AuthenticatorAssertionResponseValidator::create(
            $this->ceremonyFactory->requestCeremony(),
        );

        $varDir = $_ENV['VAR_DIR'] ?? __DIR__ . '/../var';
        $this->userStore = new UserStore($varDir . '/users.json');
        $this->credentialStore = new CredentialStore($varDir . '/credentials.json', $this->serializer);
    }
}
