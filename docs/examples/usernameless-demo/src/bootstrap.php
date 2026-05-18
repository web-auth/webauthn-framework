<?php

declare(strict_types=1);

namespace App\UsernamelessDemo;

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
    fwrite(\STDERR, "Run `composer install` in docs/examples/usernameless-demo/ first.\n");
    exit(1);
}
require_once $autoload;

require_once __DIR__ . '/UserStore.php';
require_once __DIR__ . '/CredentialStore.php';

/**
 * Minimal service container for the usernameless demo.
 *
 * Same wiring as the basic-demo: a serializer, an attestation statement
 * support manager (none format only), a COSE algorithm manager (ES256 +
 * RS256), and the two ceremony validators on top of a CeremonyStepManager
 * configured with the relying party's allowed origins. The difference with
 * the basic-demo lives entirely in router.php and in the browser pages:
 *
 *  - registration uses `residentKey: required` and
 *    `userVerification: required` so the authenticator stores a discoverable
 *    credential and remembers the user handle locally;
 *  - login posts an assertion that the server resolves to a user via the
 *    credential id alone (no username), then via the user handle returned
 *    by the authenticator in `response.userHandle`.
 *
 * Persistence is delegated to two JSON-file stores. Production code MUST
 * replace them with a real database behind the framework's repository
 * interfaces.
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
        $this->relyingPartyName = 'Usernameless WebAuthn Demo';
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
