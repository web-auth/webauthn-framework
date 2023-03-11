<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CredentialOptionsBuilder;

use function count;
use const FILTER_VALIDATE_BOOLEAN;
use function is_array;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\PublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class ProfileBasedCreationOptionsBuilder implements PublicKeyCredentialCreationOptionsBuilder
{
    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialSourceRepository $credentialSourceRepository,
        private readonly PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private readonly string $profile,
    ) {
    }

    public function getFromRequest(
        Request $request,
        PublicKeyCredentialUserEntity $userEntity
    ): PublicKeyCredentialCreationOptions {
        $format = method_exists(
            $request,
            'getContentTypeFormat'
        ) ? $request->getContentTypeFormat() : $request->getContentType();
        $format === 'json' || throw new BadRequestHttpException('Only JSON content type allowed');
        $content = $request->getContent();

        $excludedCredentials = $this->getCredentials($userEntity);
        $creationOptionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);
        $authenticatorSelectionData = $creationOptionsRequest->authenticatorSelection;
        $authenticatorSelection = null;
        if (is_array($authenticatorSelectionData)) {
            $authenticatorSelection = AuthenticatorSelectionCriteria::createFromArray($authenticatorSelectionData);
        } elseif ($creationOptionsRequest->userVerification !== null || $creationOptionsRequest->residentKey !== null || $creationOptionsRequest->authenticatorAttachment !== null) {
            $authenticatorSelection = AuthenticatorSelectionCriteria::create()
                ->setUserVerification(
                    $creationOptionsRequest->userVerification ?? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
                )
                ->setAuthenticatorAttachment($creationOptionsRequest->authenticatorAttachment);
            if ($creationOptionsRequest->requireResidentKey !== null) {
                $authenticatorSelection->setRequireResidentKey(
                    filter_var($creationOptionsRequest->requireResidentKey, FILTER_VALIDATE_BOOLEAN)
                );
            }
            if ($creationOptionsRequest->residentKey !== null) {
                $authenticatorSelection->setResidentKey($creationOptionsRequest->residentKey);
            }
        }
        $extensions = $creationOptionsRequest->extensions;
        if (is_array($extensions)) {
            $extensions = AuthenticationExtensionsClientInputs::createFromArray($extensions);
        }

        return $this->publicKeyCredentialCreationOptionsFactory->create(
            $this->profile,
            $userEntity,
            $excludedCredentials,
            $authenticatorSelection,
            $creationOptionsRequest->attestation,
            $extensions
        );
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    private function getCredentials(PublicKeyCredentialUserEntity $userEntity): array
    {
        $credentialSources = $this->credentialSourceRepository->findAllForUserEntity($userEntity);

        return array_map(
            static fn (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor => $credential->getPublicKeyCredentialDescriptor(),
            $credentialSources
        );
    }

    private function getServerPublicKeyCredentialCreationOptionsRequest(
        string $content
    ): PublicKeyCredentialCreationOptionsRequest {
        $data = $this->serializer->deserialize($content, PublicKeyCredentialCreationOptionsRequest::class, 'json');
        $errors = $this->validator->validate($data);
        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            throw new RuntimeException(implode("\n", $messages));
        }

        return $data;
    }
}
