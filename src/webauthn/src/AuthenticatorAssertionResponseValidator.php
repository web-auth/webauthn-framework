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
use InvalidArgumentException;
use function is_array;
use function is_string;
use function parse_url;
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
    private readonly Decoder $decoder;

    private CounterChecker $counterChecker;

    private LoggerInterface $logger;

    public function __construct(
        private readonly PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        private readonly TokenBindingHandler $tokenBindingHandler,
        private readonly ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        private readonly ?Manager $algorithmManager,
    ) {
        $this->decoder = Decoder::create();
        $this->counterChecker = new ThrowExceptionIfInvalid();
        $this->logger = new NullLogger();
    }

    public static function create(
        PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository,
        TokenBindingHandler $tokenBindingHandler,
        ExtensionOutputCheckerHandler $extensionOutputCheckerHandler,
        ?Manager $algorithmManager,
    ): self {
        return new self(
            $publicKeyCredentialSourceRepository,
            $tokenBindingHandler,
            $extensionOutputCheckerHandler,
            $algorithmManager
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
            if (count($publicKeyCredentialRequestOptions->getAllowCredentials()) !== 0) {
                $this->isCredentialIdAllowed(
                    $credentialId,
                    $publicKeyCredentialRequestOptions->getAllowCredentials()
                ) || throw new InvalidArgumentException('The credential ID is not allowed.');
            }

            $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId(
                $credentialId
            );
            $publicKeyCredentialSource !== null || throw new InvalidArgumentException('The credential ID is invalid.');

            $attestedCredentialData = $publicKeyCredentialSource->getAttestedCredentialData();
            $credentialUserHandle = $publicKeyCredentialSource->getUserHandle();
            $responseUserHandle = $authenticatorAssertionResponse->getUserHandle();

            if ($userHandle !== null) { //If the user was identified before the authentication ceremony was initiated,
                $credentialUserHandle === $userHandle || throw new InvalidArgumentException('Invalid user handle');
                if ($responseUserHandle !== null && $responseUserHandle !== '') {
                    $credentialUserHandle === $responseUserHandle || throw new InvalidArgumentException(
                        'Invalid user handle'
                    );
                }
            } else {
                ($responseUserHandle !== '' && $credentialUserHandle === $responseUserHandle) || throw new InvalidArgumentException(
                    'Invalid user handle'
                );
            }

            $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
            $credentialPublicKey !== null || throw new InvalidArgumentException('No public key available.');
            $isU2F = U2FPublicKey::isU2FKey($credentialPublicKey);
            if ($isU2F === true) {
                $credentialPublicKey = U2FPublicKey::convertToCoseKey($credentialPublicKey);
            }
            $stream = new StringStream($credentialPublicKey);
            $credentialPublicKeyStream = $this->decoder->decode($stream);
            $stream->isEOF() || throw new InvalidArgumentException('Invalid key. Presence of extra bytes.');
            $stream->close();

            $C = $authenticatorAssertionResponse->getClientDataJSON();

            $C->getType() === 'webauthn.get' || throw new InvalidArgumentException(
                'The client data type is not "webauthn.get".'
            );
            hash_equals(
                $publicKeyCredentialRequestOptions->getChallenge(),
                $C->getChallenge()
            ) || throw new InvalidArgumentException('Invalid challenge.');

            $rpId = $publicKeyCredentialRequestOptions->getRpId() ?? $request->getUri()
                ->getHost();
            $facetId = $this->getFacetId(
                $rpId,
                $publicKeyCredentialRequestOptions->getExtensions(),
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->getExtensions()
            );
            $parsedRelyingPartyId = parse_url($C->getOrigin());
            is_array($parsedRelyingPartyId) || throw new InvalidArgumentException('Invalid origin');
            if (! in_array($facetId, $securedRelyingPartyId, true)) {
                $scheme = $parsedRelyingPartyId['scheme'] ?? '';
                $scheme === 'https' || throw new InvalidArgumentException('Invalid scheme. HTTPS required.');
            }
            $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
            $clientDataRpId !== '' || throw new InvalidArgumentException('Invalid origin rpId.');
            $rpIdLength = mb_strlen($facetId);
            mb_substr(
                '.' . $clientDataRpId,
                -($rpIdLength + 1)
            ) === '.' . $facetId || throw new InvalidArgumentException('rpId mismatch.');

            if ($C->getTokenBinding() !== null) {
                $this->tokenBindingHandler->check($C->getTokenBinding(), $request);
            }

            $rpIdHash = hash('sha256', $isU2F ? $C->getOrigin() : $facetId, true);
            hash_equals(
                $rpIdHash,
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->getRpIdHash()
            ) || throw new InvalidArgumentException('rpId hash mismatch.');

            if ($publicKeyCredentialRequestOptions->getUserVerification() === AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED) {
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->isUserPresent() || throw new InvalidArgumentException('User was not present');
                $authenticatorAssertionResponse->getAuthenticatorData()
                    ->isUserVerified() || throw new InvalidArgumentException('User authentication required.');
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
            $credentialPublicKeyStream instanceof Normalizable || throw new InvalidArgumentException(
                'Invalid attestation object. Unexpected object.'
            );
            $normalizedData = $credentialPublicKeyStream->normalize();
            is_array($normalizedData) || throw new InvalidArgumentException(
                'Invalid attestation object. Unexpected object.'
            );
            $coseKey = Key::create($normalizedData);
            $algorithm = $this->algorithmManager?->get($coseKey->alg());
            $algorithm instanceof Signature || throw new InvalidArgumentException(
                'Invalid algorithm identifier. Should refer to a signature algorithm'
            );
            $signature = CoseSignatureFixer::fix($signature, $algorithm);
            $algorithm->verify($dataToVerify, $coseKey, $signature) || throw new InvalidArgumentException(
                'Invalid signature.'
            );

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
            ->value();
        $wasUsed = $authenticationExtensionsClientOutputs->get('appid')
            ->value();
        if (! is_string($appId) || $wasUsed !== true) {
            return $rpId;
        }

        return $appId;
    }
}
