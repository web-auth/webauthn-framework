<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CredentialOptionsBuilder;

use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\PublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use function count;
use function is_array;

final class ProfileBasedCreationOptionsBuilder implements PublicKeyCredentialCreationOptionsBuilder
{
    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialSourceRepositoryInterface $credentialSourceRepository,
        private readonly PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private readonly string $profile,
    ) {
    }

    public function getFromRequest(
        Request $request,
        PublicKeyCredentialUserEntity $userEntity
    ): PublicKeyCredentialCreationOptions {
        $format = $request->getContentTypeFormat();
        $format === 'json' || throw new BadRequestHttpException('Only JSON content type allowed');
        $content = $request->getContent();

        $excludedCredentials = $this->getCredentials($userEntity);
        $optionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);
        $authenticatorSelection = null;
        if ($optionsRequest->userVerification !== null || $optionsRequest->residentKey !== null || $optionsRequest->authenticatorAttachment !== null) {
            $residentKey = $optionsRequest->residentKey ?? null;
            $authenticatorSelection = AuthenticatorSelectionCriteria::create(
                $optionsRequest->authenticatorAttachment,
                $optionsRequest->userVerification ?? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                $residentKey
            );
        }
        $extensions = null;
        if (is_array($optionsRequest->extensions)) {
            $extensions = AuthenticationExtensions::create(array_map(
                static fn (string $name, mixed $data): AuthenticationExtension => AuthenticationExtension::create(
                    $name,
                    $data
                ),
                array_keys($optionsRequest->extensions),
                $optionsRequest->extensions
            ));
        }

        return $this->publicKeyCredentialCreationOptionsFactory->create(
            $this->profile,
            $userEntity,
            $excludedCredentials,
            $authenticatorSelection,
            $optionsRequest->attestation,
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
            throw new InvalidArgumentException(implode("\n", $messages));
        }

        return $data;
    }
}
