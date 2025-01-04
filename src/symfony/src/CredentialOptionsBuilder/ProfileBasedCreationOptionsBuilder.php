<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CredentialOptionsBuilder;

use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\PublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Service\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use function count;
use function is_array;
use function sprintf;
use const FILTER_VALIDATE_BOOLEAN;

final class ProfileBasedCreationOptionsBuilder implements PublicKeyCredentialCreationOptionsBuilder
{
    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialSourceRepository|PublicKeyCredentialSourceRepositoryInterface $credentialSourceRepository,
        private readonly PublicKeyCredentialCreationOptionsFactory $publicKeyCredentialCreationOptionsFactory,
        private readonly string $profile,
    ) {
        if (! $this->credentialSourceRepository instanceof PublicKeyCredentialSourceRepositoryInterface) {
            trigger_deprecation(
                'web-auth/webauthn-symfony-bundle',
                '4.6.0',
                sprintf(
                    'Since 4.6.0, the parameter "$credentialSourceRepository" expects an instance of "%s". Please implement that interface instead of "%s".',
                    PublicKeyCredentialSourceRepositoryInterface::class,
                    PublicKeyCredentialSourceRepository::class
                )
            );
        }
    }

    public function getFromRequest(
        Request $request,
        PublicKeyCredentialUserEntity $userEntity,
        bool $hideExistingExcludedCredentials = false
    ): PublicKeyCredentialCreationOptions {
        $format = method_exists(
            $request,
            'getContentTypeFormat'
        ) ? $request->getContentTypeFormat() : $request->getContentType();
        $format === 'json' || throw new BadRequestHttpException('Only JSON content type allowed');
        $content = $request->getContent();

        $excludedCredentials = $hideExistingExcludedCredentials === true ? [] : $this->getCredentials($userEntity);
        $optionsRequest = $this->getServerPublicKeyCredentialCreationOptionsRequest($content);
        $authenticatorSelectionData = $optionsRequest->authenticatorSelection;
        $authenticatorSelection = null;
        if (is_array($authenticatorSelectionData)) {
            $authenticatorSelection = AuthenticatorSelectionCriteria::createFromArray($authenticatorSelectionData);
        } elseif ($optionsRequest->userVerification !== null || $optionsRequest->residentKey !== null || $optionsRequest->authenticatorAttachment !== null) {
            $residentKey = $optionsRequest->residentKey ?? null;
            $requireResidentKey = $optionsRequest->requireResidentKey !== null ? filter_var(
                $optionsRequest->requireResidentKey,
                FILTER_VALIDATE_BOOLEAN
            ) : null;

            $authenticatorSelection = AuthenticatorSelectionCriteria::create(
                $optionsRequest->authenticatorAttachment,
                $optionsRequest->userVerification ?? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                $residentKey,
                $requireResidentKey
            );
        }
        $extensions = null;
        if (is_array($optionsRequest->extensions)) {
            $extensions = AuthenticationExtensionsClientInputs::create(array_map(
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
