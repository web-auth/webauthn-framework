<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;
use function count;
use const E_USER_DEPRECATED;
use function in_array;
use function is_string;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\Counter\CounterChecker;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\TokenBinding\TokenBindingHandler;
use Webauthn\Util\CoseSignatureFixer;

class AuthenticatorAssertionResponseValidator
{
    private Decoder $decoder;

    private CounterChecker $counterChecker;

    private LoggerInterface $logger;

    public function __construct(
        private PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        private TokenBindingHandler $tokenBindingHandler,
        private ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        private ?Manager $algorithmManager,
        ?CounterChecker $counterChecker = null,
        ?LoggerInterface $logger = null
    ) {
        if ($logger !== null) {
            @trigger_error(
                'The argument "logger" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setLogger".',
                E_USER_DEPRECATED
            );
        }
        if ($counterChecker !== null) {
            @trigger_error(
                'The argument "counterChecker" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setCounterChecker".',
                E_USER_DEPRECATED
            );
        }
        $this->decoder = new Decoder(new TagObjectManager(), new OtherObjectManager());
        $this->counterChecker = $counterChecker ?? new ThrowExceptionIfInvalid();
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#verifying-assertion
     */
    public function check(
        string $credentialId,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ServerRequestInterface $request,
        ?string $userHandle,
        array $securedRelyingPartyId = []
    ): PublicKeyCredentialSource {
        try {
            $this->logger->info('Checking the authenticator assertion response', [
                'credentialId' => $credentialId,
                'authenticatorAssertionResponse' => $authenticatorAssertionResponse,
                'publicKeyCredentialRequestOptions' => $publicKeyCredentialRequestOptions,
                'host' => $request->getUri()
                    ->getHost(),
                'userHandle' => $userHandle,
            ]);
            /** @see 7.2.1 */
            if (count($publicKeyCredentialRequestOptions->getAllowCredentials()) !== 0) {
                Assertion::true(
                    $this->isCredentialIdAllowed(
                        $credentialId,
                        $publicKeyCredentialRequestOptions->getAllowCredentials()
                    ),
                    'The credential ID is not allowed.'
                );
            }

            /** @see 7.2.2 */
            $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId(
                $credentialId
            );
            Assertion::notNull($publicKeyCredentialSource, 'The credential ID is invalid.');

            /** @see 7.2.3 */
            $attestedCredentialData = $publicKeyCredentialSource->getAttestedCredentialData();
            $credentialUserHandle = $publicKeyCredentialSource->getUserHandle();
            $responseUserHandle = $authenticatorAssertionResponse->getUserHandle();

            /** @see 7.2.2 User Handle*/
            if ($userHandle !== null) { //If the user was identified before the authentication ceremony was initiated,
                Assertion::eq($credentialUserHandle, $userHandle, 'Invalid user handle');
                if ($responseUserHandle !== null && $responseUserHandle !== '') {
                    Assertion::eq($credentialUserHandle, $responseUserHandle, 'Invalid user handle');
                }
            } else {
                Assertion::notEmpty($responseUserHandle, 'User handle is mandatory');
                Assertion::eq($credentialUserHandle, $responseUserHandle, 'Invalid user handle');
            }

            $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
            Assertion::notNull($credentialPublicKey, 'No public key available.');
            $stream = new StringStream($credentialPublicKey);
            $credentialPublicKeyStream = $this->decoder->decode($stream);
            Assertion::true($stream->isEOF(), 'Invalid key. Presence of extra bytes.');
            $stream->close();

            /** @see 7.2.4 */
            /** @see 7.2.5 */
            //Nothing to do. Use of objects directly

            /** @see 7.2.6 */
            $C = $authenticatorAssertionResponse->getClientDataJSON();

            /** @see 7.2.7 */
            Assertion::eq('webauthn.get', $C->getType(), 'The client data type is not "webauthn.get".');

            /** @see 7.2.8 */
            Assertion::true(
                hash_equals($publicKeyCredentialRequestOptions->getChallenge(), $C->getChallenge()),
                'Invalid challenge.'
            );

            /** @see 7.2.9 */
            $rpId = $publicKeyCredentialRequestOptions->getRpId() ?? $request->getUri()
                ->getHost()
            ;
            $facetId = $this->getFacetId(
                $rpId,
                $publicKeyCredentialRequestOptions->getExtensions(),
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->getExtensions()
            );
            $parsedRelyingPartyId = parse_url($C->getOrigin());
            Assertion::isArray($parsedRelyingPartyId, 'Invalid origin');
            if (! in_array($facetId, $securedRelyingPartyId, true)) {
                $scheme = $parsedRelyingPartyId['scheme'] ?? '';
                Assertion::eq('https', $scheme, 'Invalid scheme. HTTPS required.');
            }
            $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
            Assertion::notEmpty($clientDataRpId, 'Invalid origin rpId.');
            $rpIdLength = mb_strlen($facetId);
            Assertion::eq(mb_substr('.' . $clientDataRpId, -($rpIdLength + 1)), '.' . $facetId, 'rpId mismatch.');

            /** @see 7.2.10 */
            if ($C->getTokenBinding() !== null) {
                $this->tokenBindingHandler->check($C->getTokenBinding(), $request);
            }

            /** @see 7.2.11 */
            $rpIdHash = hash('sha256', $facetId, true);
            Assertion::true(
                hash_equals($rpIdHash, $authenticatorAssertionResponse->getAuthenticatorData()->getRpIdHash()),
                'rpId hash mismatch.'
            );

            /** @see 7.2.12 */
            Assertion::true(
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->isUserPresent(),
                'User was not present'
            );
            /** @see 7.2.13 */
            if ($publicKeyCredentialRequestOptions->getUserVerification() === AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED) {
                Assertion::true(
                    $authenticatorAssertionResponse->getAuthenticatorData()
                        ->isUserVerified(),
                    'User authentication required.'
                );
            }

            /** @see 7.2.14 */
            $extensionsClientOutputs = $authenticatorAssertionResponse->getAuthenticatorData()
                ->getExtensions()
            ;
            if ($extensionsClientOutputs !== null) {
                $this->extensionOutputCheckerHandler->check(
                    $publicKeyCredentialRequestOptions->getExtensions(),
                    $extensionsClientOutputs
                );
            }

            /** @see 7.2.15 */
            $getClientDataJSONHash = hash(
                'sha256',
                $authenticatorAssertionResponse->getClientDataJSON()
                    ->getRawData(),
                true
            );

            /** @see 7.2.16 */
            $dataToVerify = $authenticatorAssertionResponse->getAuthenticatorData()
                ->getAuthData() . $getClientDataJSONHash;
            $signature = $authenticatorAssertionResponse->getSignature();
            $coseKey = new Key($credentialPublicKeyStream->getNormalizedData());
            $algorithm = $this->algorithmManager->get($coseKey->alg());
            Assertion::isInstanceOf(
                $algorithm,
                Signature::class,
                'Invalid algorithm identifier. Should refer to a signature algorithm'
            );
            $signature = CoseSignatureFixer::fix($signature, $algorithm);
            Assertion::true($algorithm->verify($dataToVerify, $coseKey, $signature), 'Invalid signature.');

            /** @see 7.2.17 */
            $storedCounter = $publicKeyCredentialSource->getCounter();
            $responseCounter = $authenticatorAssertionResponse->getAuthenticatorData()
                ->getSignCount()
            ;
            if ($responseCounter !== 0 || $storedCounter !== 0) {
                $this->counterChecker->check($publicKeyCredentialSource, $responseCounter);
            }
            $publicKeyCredentialSource->setCounter($responseCounter);
            $this->publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);

            /** @see 7.2.18 */
            //All good. We can continue.
            $this->logger->info('The assertion is valid');
            $this->logger->debug('Public Key Credential Source', [
                'publicKeyCredentialSource' => $publicKeyCredentialSource,
            ]);

            return $publicKeyCredentialSource;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function setCounterChecker(CounterChecker $counterChecker): self
    {
        $this->counterChecker = $counterChecker;

        return $this;
    }

    /**
     * @param array<PublicKeyCredentialDescriptor> $allowedCredentials
     */
    private function isCredentialIdAllowed(string $credentialId, array $allowedCredentials): bool
    {
        foreach ($allowedCredentials as $allowedCredential) {
            if (hash_equals($allowedCredential->getId(), $credentialId)) {
                return true;
            }
        }

        return false;
    }

    private function getFacetId(
        string $rpId,
        AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs,
        ?AuthenticationExtensionsClientOutputs $authenticationExtensionsClientOutputs
    ): string {
        if ($authenticationExtensionsClientOutputs === null || ! $authenticationExtensionsClientInputs->has(
            'appid'
        ) || ! $authenticationExtensionsClientOutputs->has('appid')) {
            return $rpId;
        }
        $appId = $authenticationExtensionsClientInputs->get('appid')
            ->value()
        ;
        $wasUsed = $authenticationExtensionsClientOutputs->get('appid')
            ->value()
        ;
        if (! is_string($appId) || $wasUsed !== true) {
            return $rpId;
        }

        return $appId;
    }
}
