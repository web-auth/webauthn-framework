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
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\StatusReportRepository;
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
 *
 * Per-verifier overrides supported through fluent setters (build a fresh
 * {@see CeremonyStepManager} on top of a clone of the autowired factory, so the
 * factory's global state stays unchanged):
 *
 *   - {@see self::withAllowedOrigins()} / {@see self::withAllowSubdomains()}
 *     to scope the accepted origins for this verification only;
 *   - {@see self::withMetadata()} to plug Metadata Statement / Status Report /
 *     Certificate Chain validation services for this verification only.
 */
final class WebauthnAttestationVerifier extends AbstractWebauthnVerifier
{
    private bool $saveCredential = true;

    private ?MetadataStatementRepository $metadataStatementRepository = null;

    private ?StatusReportRepository $statusReportRepository = null;

    private ?CertificateChainValidator $certificateChainValidator = null;

    private bool $metadataDisabled = false;

    public function __construct(
        SerializerInterface $serializer,
        OptionsStorage $storage,
        private readonly AuthenticatorAttestationResponseValidator $validator,
        private readonly AuthenticatorAttestationResponseValidator $conditionalValidator,
        private CredentialRecordRepositoryInterface $repository,
        private readonly CeremonyStepManagerFactory $ceremonyStepManagerFactory,
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

    /**
     * Override the bundle's `CredentialRecordRepositoryInterface` for this single
     * verification (e.g. multi-tenant setups where each route writes to its own
     * credential store).
     */
    public function withCredentialRepository(CredentialRecordRepositoryInterface $repository): static
    {
        $clone = clone $this;
        $clone->repository = $repository;

        return $clone;
    }

    /**
     * Override the Metadata Statement support for this verification only. Used
     * either to swap the globally-configured services (different MDS / Status /
     * Cert chain validator on a specific endpoint) or to plug metadata
     * validation on a single endpoint when the global `webauthn.metadata`
     * config is disabled.
     *
     * The autowired {@see CeremonyStepManagerFactory} is cloned and reconfigured
     * for the call so the singleton's global state stays untouched.
     */
    public function withMetadata(
        MetadataStatementRepository $metadataStatementRepository,
        StatusReportRepository $statusReportRepository,
        CertificateChainValidator $certificateChainValidator,
    ): static {
        $clone = clone $this;
        $clone->metadataStatementRepository = $metadataStatementRepository;
        $clone->statusReportRepository = $statusReportRepository;
        $clone->certificateChainValidator = $certificateChainValidator;
        $clone->metadataDisabled = false;

        return $clone;
    }

    /**
     * Disable Metadata Statement validation for this verification only. Useful
     * when the bundle's global `webauthn.metadata` configuration is enabled but
     * a specific endpoint should NOT enforce metadata checks (e.g. a registration
     * route open to authenticators that have no published Metadata Statement).
     */
    public function withoutMetadata(): static
    {
        $clone = clone $this;
        $clone->metadataStatementRepository = null;
        $clone->statusReportRepository = null;
        $clone->certificateChainValidator = null;
        $clone->metadataDisabled = true;

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

        $isConditional = $options->mediation === PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL;
        $validator = $this->resolveValidator($isConditional);

        $credentialRecord = $validator->check($response, $options, $request->getHost());

        if ($this->saveCredential) {
            $this->persist($credentialRecord);
        }

        return $credentialRecord;
    }

    private function resolveValidator(bool $isConditional): AuthenticatorAttestationResponseValidator
    {
        if (! $this->hasOverrides()) {
            return $isConditional ? $this->conditionalValidator : $this->validator;
        }

        $factory = clone $this->ceremonyStepManagerFactory;
        if ($this->metadataDisabled) {
            $factory->disableMetadataStatementSupport();
        } elseif ($this->metadataStatementRepository !== null
            && $this->statusReportRepository !== null
            && $this->certificateChainValidator !== null
        ) {
            $factory->enableMetadataStatementSupport(
                $this->metadataStatementRepository,
                $this->statusReportRepository,
                $this->certificateChainValidator,
            );
        }
        if ($this->topOriginValidatorIsOverridden) {
            $this->topOriginValidatorOverride === null
                ? $factory->disableTopOriginValidator()
                : $factory->enableTopOriginValidator($this->topOriginValidatorOverride);
        }

        $csm = $isConditional
            ? $factory->conditionalCreateCeremony($this->allowedOriginsOverride, $this->allowSubdomainsOverride)
            : $factory->creationCeremony($this->allowedOriginsOverride, $this->allowSubdomainsOverride);

        $scoped = new AuthenticatorAttestationResponseValidator($csm);
        $scoped->setLogger($this->logger);
        $scoped->setEventDispatcher($this->eventDispatcher);

        return $scoped;
    }

    private function hasOverrides(): bool
    {
        return $this->allowedOriginsOverride !== null
            || $this->metadataStatementRepository !== null
            || $this->metadataDisabled
            || $this->topOriginValidatorIsOverridden;
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
