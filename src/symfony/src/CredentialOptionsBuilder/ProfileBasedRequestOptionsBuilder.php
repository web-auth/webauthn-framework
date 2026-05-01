<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CredentialOptionsBuilder;

use function count;
use function is_array;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\CredentialRecord;
use Webauthn\FakeCredentialGenerator;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

final readonly class ProfileBasedRequestOptionsBuilder implements PublicKeyCredentialRequestOptionsBuilder
{
    public function __construct(
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private PublicKeyCredentialUserEntityRepositoryInterface $userEntityRepository,
        private CredentialRecordRepositoryInterface $credentialSourceRepository,
        private PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory,
        private string $profile,
        private null|FakeCredentialGenerator $fakeCredentialGenerator = null,
        private ClientOverridePolicy $overridePolicy = new ClientOverridePolicy(),
    ) {
    }

    public function getFromRequest(
        Request $request,
        ?PublicKeyCredentialUserEntity &$userEntity = null
    ): PublicKeyCredentialRequestOptions {
        $format = $request->getContentTypeFormat();
        $format === 'json' || throw new BadRequestHttpException('Only JSON content type allowed');
        $content = $request->getContent();
        $optionsRequest = $this->getServerPublicKeyCredentialRequestOptionsRequest($content);

        $userEntity = $optionsRequest->username === null ? null : $this->userEntityRepository->findOneByUsername(
            $optionsRequest->username
        );

        $allowedCredentials = match (true) {
            $userEntity === null && $optionsRequest->username === null, $userEntity === null && $optionsRequest->username !== null && $this->fakeCredentialGenerator === null => [],
            $userEntity === null && $optionsRequest->username !== null && $this->fakeCredentialGenerator !== null => $this->fakeCredentialGenerator->generate(
                $request,
                $optionsRequest->username
            ),
            $userEntity !== null => $this->getCredentials($userEntity),
            default => [],
        };

        // Apply override policy to determine effective values
        /** @var ?string $userVerification */
        $userVerification = $this->overridePolicy->getEffectiveValue(
            'user_verification',
            $optionsRequest->userVerification,
            null // Will fallback to profile
        );

        $extensions = $this->getEffectiveExtensions($optionsRequest);

        return $this->publicKeyCredentialRequestOptionsFactory->create(
            $this->profile,
            $allowedCredentials,
            $userVerification,
            $extensions
        );
    }

    private function getEffectiveExtensions(
        ServerPublicKeyCredentialRequestOptionsRequest $optionsRequest
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

    private function getServerPublicKeyCredentialRequestOptionsRequest(
        string $content
    ): ServerPublicKeyCredentialRequestOptionsRequest {
        $data = $this->serializer->deserialize(
            $content,
            ServerPublicKeyCredentialRequestOptionsRequest::class,
            JsonEncoder::FORMAT,
            [
                AbstractObjectNormalizer::DISABLE_TYPE_ENFORCEMENT => true,
            ]
        );
        $errors = $this->validator->validate($data);
        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            throw new BadRequestHttpException(implode("\n", $messages));
        }

        return $data;
    }
}
