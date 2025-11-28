<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CredentialOptionsBuilder;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepositoryInterface;
use Webauthn\Bundle\Service\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\CredentialRecord;
use Webauthn\FakeCredentialGenerator;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use function count;
use function is_array;

final readonly class ProfileBasedRequestOptionsBuilder implements PublicKeyCredentialRequestOptionsBuilder
{
    public function __construct(
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private PublicKeyCredentialUserEntityRepositoryInterface $userEntityRepository,
        private PublicKeyCredentialSourceRepositoryInterface $credentialSourceRepository,
        private PublicKeyCredentialRequestOptionsFactory $publicKeyCredentialRequestOptionsFactory,
        private string $profile,
        private null|FakeCredentialGenerator $fakeCredentialGenerator = null,
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
        $userEntity = $optionsRequest->username === null ? null : $this->userEntityRepository->findOneByUsername(
            $optionsRequest->username
        );

        $allowedCredentials = match (true) {
            $userEntity === null && $optionsRequest->username === null, $userEntity === null && $optionsRequest->username !== null && $this->fakeCredentialGenerator === null => [],
            $userEntity === null && $optionsRequest->username !== null && $this->fakeCredentialGenerator !== null => $this->fakeCredentialGenerator->generate(
                $request,
                $optionsRequest->username
            ),
            default => $this->getCredentials($userEntity),
        };

        return $this->publicKeyCredentialRequestOptionsFactory->create(
            $this->profile,
            $allowedCredentials,
            $optionsRequest->userVerification,
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
            static fn (CredentialRecord|PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor => $credential->getPublicKeyCredentialDescriptor(),
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
