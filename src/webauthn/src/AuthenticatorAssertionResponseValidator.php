<?php

declare(strict_types=1);

namespace Webauthn;

use CBOR\Decoder;
use CBOR\Normalizable;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;
use function count;
use function in_array;
use function is_array;
use function is_string;
use function parse_url;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\Counter\CounterChecker;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\Event\AuthenticatorAssertionResponseValidationFailedEvent;
use Webauthn\Event\AuthenticatorAssertionResponseValidationSucceededEvent;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\NullEventDispatcher;
use Webauthn\TokenBinding\TokenBindingHandler;
use Webauthn\Util\CoseSignatureFixer;

class AuthenticatorAssertionResponseValidator implements CanLogData, CanDispatchEvents
{
    private readonly Decoder $decoder;

    private CounterChecker $counterChecker;

    private LoggerInterface $logger;

    private EventDispatcherInterface $eventDispatcher;

    public function __construct(
        private readonly PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        private readonly ?TokenBindingHandler $tokenBindingHandler,
        private readonly ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        private readonly ?Manager $algorithmManager,
        ?EventDispatcherInterface $eventDispatcher = null,
    ) {
        if ($this->tokenBindingHandler !== null) {
            trigger_deprecation(
                'web-auth/webauthn-symfony-bundle',
                '4.3.0',
                'The parameter "$tokenBindingHandler" is deprecated since 4.3.0 and will be removed in 5.0.0. Please set "null" instead.'
            );
        }
        if ($eventDispatcher === null) {
            $this->eventDispatcher = new NullEventDispatcher();
        } else {
            $this->eventDispatcher = $eventDispatcher;
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '4.5.0',
                'The parameter "$eventDispatcher" is deprecated since 4.5.0 will be removed in 5.0.0. Please use `setEventDispatcher` instead.'
            );
        }
        $this->decoder = Decoder::create();
        $this->counterChecker = new ThrowExceptionIfInvalid();
        $this->logger = new NullLogger();
    }

    public static function create(
        PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        ?TokenBindingHandler $tokenBindingHandler,
        ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        ?Manager $algorithmManager,
        ?EventDispatcherInterface $eventDispatcher = null
    ): self {
        return new self(
            $publicKeyCredentialSourceRepository,
            $tokenBindingHandler,
            $extensionOutputCheckerHandler,
            $algorithmManager,
            $eventDispatcher,
        );
    }

    /**
     * @param string[] $securedRelyingPartyId
     *
     * @see https://www.w3.org/TR/webauthn/#verifying-assertion
     */
    public function check(
        string $credentialId,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ServerRequestInterface|string $request,
        ?string $userHandle,
        array $securedRelyingPartyId = []
    ): PublicKeyCredentialSource {
        if ($request instanceof ServerRequestInterface) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '4.5.0',
                sprintf(
                    'Passing a %s to the method `check` of the class "%s" is deprecated since 4.5.0 and will be removed in 5.0.0. Please inject the host as a string instead.',
                    ServerRequestInterface::class,
                    self::class
                )
            );
        }
        try {
            $this->logger->info('Checking the authenticator assertion response', [
                'credentialId' => $credentialId,
                'authenticatorAssertionResponse' => $authenticatorAssertionResponse,
                'publicKeyCredentialRequestOptions' => $publicKeyCredentialRequestOptions,
                'host' => is_string($request) ? $request : $request->getUri()
                    ->getHost(),
                'userHandle' => $userHandle,
            ]);
            if (count($publicKeyCredentialRequestOptions->getAllowCredentials()) !== 0) {
                $this->isCredentialIdAllowed(
                    $credentialId,
                    $publicKeyCredentialRequestOptions->getAllowCredentials()
                ) || throw AuthenticatorResponseVerificationException::create('The credential ID is not allowed.');
            }
            $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId(
                $credentialId
            );
            $publicKeyCredentialSource !== null || throw AuthenticatorResponseVerificationException::create(
                'The credential ID is invalid.'
            );
            $attestedCredentialData = $publicKeyCredentialSource->getAttestedCredentialData();
            $credentialUserHandle = $publicKeyCredentialSource->getUserHandle();
            $responseUserHandle = $authenticatorAssertionResponse->getUserHandle();
            if ($userHandle !== null) { //If the user was identified before the authentication ceremony was initiated,
                $credentialUserHandle === $userHandle || throw AuthenticatorResponseVerificationException::create(
                    'Invalid user handle'
                );
                if ($responseUserHandle !== null && $responseUserHandle !== '') {
                    $credentialUserHandle === $responseUserHandle || throw AuthenticatorResponseVerificationException::create(
                        'Invalid user handle'
                    );
                }
            } else {
                ($responseUserHandle !== '' && $credentialUserHandle === $responseUserHandle) || throw AuthenticatorResponseVerificationException::create(
                    'Invalid user handle'
                );
            }
            $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
            $credentialPublicKey !== null || throw AuthenticatorResponseVerificationException::create(
                'No public key available.'
            );
            $isU2F = U2FPublicKey::isU2FKey($credentialPublicKey);
            if ($isU2F === true) {
                $credentialPublicKey = U2FPublicKey::convertToCoseKey($credentialPublicKey);
            }
            $stream = new StringStream($credentialPublicKey);
            $credentialPublicKeyStream = $this->decoder->decode($stream);
            $stream->isEOF() || throw AuthenticatorResponseVerificationException::create(
                'Invalid key. Presence of extra bytes.'
            );
            $stream->close();
            $C = $authenticatorAssertionResponse->getClientDataJSON();
            $C->getType() === 'webauthn.get' || throw AuthenticatorResponseVerificationException::create(
                'The client data type is not "webauthn.get".'
            );
            hash_equals(
                $publicKeyCredentialRequestOptions->getChallenge(),
                $C->getChallenge()
            ) || throw AuthenticatorResponseVerificationException::create('Invalid challenge.');
            $rpId = $publicKeyCredentialRequestOptions->getRpId() ?? (is_string(
                $request
            ) ? $request : $request->getUri()
                ->getHost());
            $facetId = $this->getFacetId(
                $rpId,
                $publicKeyCredentialRequestOptions->getExtensions(),
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->getExtensions()
            );
            $parsedRelyingPartyId = parse_url($C->getOrigin());
            is_array($parsedRelyingPartyId) || throw AuthenticatorResponseVerificationException::create(
                'Invalid origin'
            );
            if (! in_array($facetId, $securedRelyingPartyId, true)) {
                $scheme = $parsedRelyingPartyId['scheme'] ?? '';
                $scheme === 'https' || throw AuthenticatorResponseVerificationException::create(
                    'Invalid scheme. HTTPS required.'
                );
            }
            $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
            $clientDataRpId !== '' || throw AuthenticatorResponseVerificationException::create('Invalid origin rpId.');
            $rpIdLength = mb_strlen($facetId);
            mb_substr(
                '.' . $clientDataRpId,
                -($rpIdLength + 1)
            ) === '.' . $facetId || throw AuthenticatorResponseVerificationException::create('rpId mismatch.');
            if (! is_string($request) && $C->getTokenBinding() !== null) {
                $this->tokenBindingHandler?->check($C->getTokenBinding(), $request);
            }
            $rpIdHash = hash('sha256', $isU2F ? $C->getOrigin() : $facetId, true);
            hash_equals(
                $rpIdHash,
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->getRpIdHash()
            ) || throw AuthenticatorResponseVerificationException::create('rpId hash mismatch.');
            if ($publicKeyCredentialRequestOptions->getUserVerification() === AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED) {
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->isUserPresent() || throw AuthenticatorResponseVerificationException::create(
                        'User was not present'
                    );
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->isUserVerified() || throw AuthenticatorResponseVerificationException::create(
                        'User authentication required.'
                    );
            }
            $extensionsClientOutputs = $authenticatorAssertionResponse->getAuthenticatorData()
                ->getExtensions();
            if ($extensionsClientOutputs !== null) {
                $this->extensionOutputCheckerHandler->check(
                    $publicKeyCredentialRequestOptions->getExtensions(),
                    $extensionsClientOutputs
                );
            }
            $getClientDataJSONHash = hash(
                'sha256',
                $authenticatorAssertionResponse->getClientDataJSON()
                    ->getRawData(),
                true
            );
            $dataToVerify = $authenticatorAssertionResponse->getAuthenticatorData()
                ->getAuthData() . $getClientDataJSONHash;
            $signature = $authenticatorAssertionResponse->getSignature();
            $credentialPublicKeyStream instanceof Normalizable || throw AuthenticatorResponseVerificationException::create(
                'Invalid attestation object. Unexpected object.'
            );
            $normalizedData = $credentialPublicKeyStream->normalize();
            is_array($normalizedData) || throw AuthenticatorResponseVerificationException::create(
                'Invalid attestation object. Unexpected object.'
            );
            $coseKey = Key::create($normalizedData);
            $algorithm = $this->algorithmManager?->get($coseKey->alg());
            $algorithm instanceof Signature || throw AuthenticatorResponseVerificationException::create(
                'Invalid algorithm identifier. Should refer to a signature algorithm'
            );
            $signature = CoseSignatureFixer::fix($signature, $algorithm);
            $algorithm->verify(
                $dataToVerify,
                $coseKey,
                $signature
            ) || throw AuthenticatorResponseVerificationException::create('Invalid signature.');
            $storedCounter = $publicKeyCredentialSource->getCounter();
            $responseCounter = $authenticatorAssertionResponse->getAuthenticatorData()
                ->getSignCount();
            if ($responseCounter !== 0 || $storedCounter !== 0) {
                $this->counterChecker->check($publicKeyCredentialSource, $responseCounter);
            }
            $publicKeyCredentialSource->setCounter($responseCounter);
            $this->publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);
            //All good. We can continue.
            $this->logger->info('The assertion is valid');
            $this->logger->debug('Public Key Credential Source', [
                'publicKeyCredentialSource' => $publicKeyCredentialSource,
            ]);
            $this->eventDispatcher->dispatch(
                $this->createAuthenticatorAssertionResponseValidationSucceededEvent(
                    $credentialId,
                    $authenticatorAssertionResponse,
                    $publicKeyCredentialRequestOptions,
                    $request,
                    $userHandle,
                    $publicKeyCredentialSource
                )
            );
            return $publicKeyCredentialSource;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            $this->eventDispatcher->dispatch(
                $this->createAuthenticatorAssertionResponseValidationFailedEvent(
                    $credentialId,
                    $authenticatorAssertionResponse,
                    $publicKeyCredentialRequestOptions,
                    $request,
                    $userHandle,
                    $throwable
                )
            );
            throw $throwable;
        }
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    public function setCounterChecker(CounterChecker $counterChecker): self
    {
        $this->counterChecker = $counterChecker;
        return $this;
    }

    protected function createAuthenticatorAssertionResponseValidationSucceededEvent(
        string $credentialId,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ServerRequestInterface|string $request,
        ?string $userHandle,
        PublicKeyCredentialSource $publicKeyCredentialSource
    ): AuthenticatorAssertionResponseValidationSucceededEvent {
        if ($request instanceof ServerRequestInterface) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '4.5.0',
                sprintf(
                    'Passing a %s to the method `createAuthenticatorAssertionResponseValidationSucceededEvent` of the class "%s" is deprecated since 4.5.0 and will be removed in 5.0.0. Please inject the host as a string instead.',
                    ServerRequestInterface::class,
                    self::class
                )
            );
        }
        return new AuthenticatorAssertionResponseValidationSucceededEvent(
            $credentialId,
            $authenticatorAssertionResponse,
            $publicKeyCredentialRequestOptions,
            $request,
            $userHandle,
            $publicKeyCredentialSource
        );
    }

    protected function createAuthenticatorAssertionResponseValidationFailedEvent(
        string $credentialId,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ServerRequestInterface|string $request,
        ?string $userHandle,
        Throwable $throwable
    ): AuthenticatorAssertionResponseValidationFailedEvent {
        if ($request instanceof ServerRequestInterface) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '4.5.0',
                sprintf(
                    'Passing a %s to the method `createAuthenticatorAssertionResponseValidationFailedEvent` of the class "%s" is deprecated since 4.5.0 and will be removed in 5.0.0. Please inject the host as a string instead.',
                    ServerRequestInterface::class,
                    self::class
                )
            );
        }
        return new AuthenticatorAssertionResponseValidationFailedEvent(
            $credentialId,
            $authenticatorAssertionResponse,
            $publicKeyCredentialRequestOptions,
            $request,
            $userHandle,
            $throwable
        );
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
            ->value();
        $wasUsed = $authenticationExtensionsClientOutputs->get('appid')
            ->value();
        if (! is_string($appId) || $wasUsed !== true) {
            return $rpId;
        }
        return $appId;
    }
}
