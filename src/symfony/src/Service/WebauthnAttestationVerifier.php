<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use function assert;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorResponse;
use Webauthn\Bundle\Exception\MissingFeatureException;
use Webauthn\Bundle\Repository\CanSaveCredentialRecord;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Verifies the {@see AuthenticatorAttestationResponse} produced at the end of a
 * registration ceremony, returned by
 * {@see WebauthnResponseVerifier::forAttestation()}.
 *
 * By default the validated credential record is persisted automatically through
 * the autowired {@see CredentialRecordRepositoryInterface}. Disable that
 * behaviour with {@see self::withSaveCredential()} if your controller wants to
 * own persistence (e.g. attach extra fields, write through a transaction).
 *
 * If the stored creation options carry the W3C `mediation: conditional` flag,
 * the verifier automatically uses the conditional creation ceremony manager
 * (which relaxes the User Verification check, per the spec).
 */
final class WebauthnAttestationVerifier extends AbstractWebauthnVerifier
{
    private bool $saveCredential = true;

    public function __construct(
        SerializerInterface $serializer,
        OptionsStorage $storage,
        private readonly AuthenticatorAttestationResponseValidator $validator,
        private readonly AuthenticatorAttestationResponseValidator $conditionalValidator,
        private readonly CredentialRecordRepositoryInterface $repository,
        private readonly string $rpId,
    ) {
        parent::__construct($serializer, $storage);
    }

    public function withSaveCredential(bool $save = true): static
    {
        $clone = clone $this;
        $clone->saveCredential = $save;

        return $clone;
    }

    protected function ensureResponseMatches(AuthenticatorResponse $response): void
    {
        $response instanceof AuthenticatorAttestationResponse || throw new BadRequestHttpException(
            'The response is not an attestation response.'
        );
    }

    protected function ensureOptionsMatch(PublicKeyCredentialOptions $options): void
    {
        $options instanceof PublicKeyCredentialCreationOptions || throw new BadRequestHttpException(
            'The stored options are not creation options.'
        );

        $options->rp->id === $this->rpId || throw new BadRequestHttpException(
            'The stored options do not match the expected Relying Party identifier.'
        );
    }

    protected function runValidation(
        Request $request,
        PublicKeyCredential $publicKeyCredential,
        AuthenticatorResponse $response,
        PublicKeyCredentialOptions $options,
        ?PublicKeyCredentialUserEntity $userEntity,
    ): CredentialRecord {
        assert($response instanceof AuthenticatorAttestationResponse);
        assert($options instanceof PublicKeyCredentialCreationOptions);

        $validator = $options->mediation === PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL
            ? $this->conditionalValidator
            : $this->validator;

        $credentialRecord = $validator->check($response, $options, $request->getHost());

        if ($this->saveCredential) {
            $this->persist($credentialRecord);
        }

        return $credentialRecord;
    }

    private function persist(CredentialRecord $credentialRecord): void
    {
        $this->repository instanceof CanSaveCredentialRecord || throw MissingFeatureException::create(
            'Unable to save the credential record.'
        );

        if ($this->repository->findOneByCredentialId($credentialRecord->publicKeyCredentialId) !== null) {
            throw new BadRequestHttpException('The credential already exists.');
        }

        $this->repository->saveCredentialRecord($credentialRecord);
    }
}
