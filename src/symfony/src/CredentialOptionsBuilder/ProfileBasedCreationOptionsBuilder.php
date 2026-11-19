<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CredentialOptionsBuilder;

use function count;
use InvalidArgumentException;
use function is_array;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\PublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialUserEntity;

final readonly class ProfileBasedCreationOptionsBuilder implements PublicKeyCredentialCreationOptionsBuilder
{
    public function __construct(
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private CredentialRecordRepositoryInterface $credentialSourceRepository,
        private PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private string $profile,
        private ClientOverridePolicy $overridePolicy = new ClientOverridePolicy(),
    ) {
    }

    public function getFromRequest(
        Request $request,
        PublicKeyCredentialUserEntity $userEntity,
        bool $hideExistingExcludedCredentials = false
    ): PublicKeyCredentialCreationOptions {
        $format = $request->getContentTypeFormat();
        $format === 'json' || throw new BadRequestHttpException('Only JSON content type allowed');
        $content = $request->getContent();

        $excludedCredentials = $hideExistingExcludedCredentials ? [] : $this->getCredentials($userEntity);
        $optionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);

        // Apply override policy to determine effective values
        $authenticatorSelection = $this->buildAuthenticatorSelectionCriteria($optionsRequest);
        $attestation = $this->getEffectiveAttestation($optionsRequest);
        $extensions = $this->getEffectiveExtensions($optionsRequest);
        $mediation = $this->getEffectiveMediation($optionsRequest);

        return $this->publicKeyCredentialCreationOptionsFactory->create(
            $this->profile,
            $userEntity,
            $excludedCredentials,
            $authenticatorSelection,
            $attestation,
            $extensions,
            $mediation,
        );
    }

    private function getEffectiveMediation(PublicKeyCredentialCreationOptionsRequest $optionsRequest): ?string
    {
        /** @var string|null */
        return $this->overridePolicy->getEffectiveValue('mediation', $optionsRequest->mediation, null);
    }

    /**
     * Each member of the criteria keeps the value of the profile, unless the client sent a value that the override
     * policy allows for that very member. Overriding the authenticator attachment or the resident key therefore never
     * resets the user verification requirement of the profile.
     */
    private function buildAuthenticatorSelectionCriteria(
        PublicKeyCredentialCreationOptionsRequest $optionsRequest
    ): AuthenticatorSelectionCriteria {
        $profileCriteria = $this->publicKeyCredentialCreationOptionsFactory->getAuthenticatorSelectionCriteria(
            $this->profile
        );

        /** @var ?string $authenticatorAttachment */
        $authenticatorAttachment = $this->overridePolicy->getEffectiveValue(
            'authenticator_attachment',
            $optionsRequest->authenticatorAttachment,
            $profileCriteria->authenticatorAttachment
        );

        /** @var string $userVerification */
        $userVerification = $this->overridePolicy->getEffectiveValue(
            'user_verification',
            $optionsRequest->userVerification,
            $profileCriteria->userVerification
        );

        /** @var ?string $residentKey */
        $residentKey = $this->overridePolicy->getEffectiveValue(
            'resident_key',
            $optionsRequest->residentKey,
            $profileCriteria->residentKey
        );

        return AuthenticatorSelectionCriteria::create($authenticatorAttachment, $userVerification, $residentKey);
    }

    private function getEffectiveAttestation(PublicKeyCredentialCreationOptionsRequest $optionsRequest): ?string
    {
        /** @var string|null */
        return $this->overridePolicy->getEffectiveValue(
            'attestation_conveyance',
            $optionsRequest->attestation,
            null // Will fallback to profile
        );
    }

    private function getEffectiveExtensions(
        PublicKeyCredentialCreationOptionsRequest $optionsRequest
    ): ?AuthenticationExtensions {
        if (! $this->overridePolicy->canOverride('extensions') || ! is_array($optionsRequest->extensions)) {
            return null; // Use profile extensions
        }

        $extensions = [];
        foreach ($optionsRequest->extensions as $name => $data) {
            $extensions[] = AuthenticationExtension::create($name, $data);
        }

        return AuthenticationExtensions::create($extensions);
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getCredentials(PublicKeyCredentialUserEntity $userEntity): array
    {
        $credentialSources = $this->credentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(
            static fn (CredentialRecord $credential): PublicKeyCredentialDescriptor => $credential->getPublicKeyCredentialDescriptor(),
            $credentialSources
        );
    }

    private function getServerPublicKeyCredentialCreationOptionsRequest(
        string $content
    ): PublicKeyCredentialCreationOptionsRequest {
        $data = $this->serializer->deserialize(
            $content,
            PublicKeyCredentialCreationOptionsRequest::class,
            JsonEncoder::FORMAT
        );
        $errors = $this->validator->validate($data);
        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            throw new InvalidArgumentException(implode("\n", $messages));
        }

        return $data;
    }
}
