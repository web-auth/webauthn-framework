<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Guesser;

use Assert\Assertion;
use function count;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class RequestBodyUserEntityGuesser implements UserEntityGuesser
{
    public function __construct(
        private SerializerInterface $serializer,
        private ValidatorInterface $validator,
        private PublicKeyCredentialUserEntityRepository $userEntityRepository
    ) {
    }

    public function findUserEntity(Request $request): PublicKeyCredentialUserEntity
    {
        Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
        $content = $request->getContent();
        Assertion::string($content, 'Invalid data');

        /** @var ServerPublicKeyCredentialCreationOptionsRequest $dto */
        $dto = $this->serializer->deserialize($content, ServerPublicKeyCredentialCreationOptionsRequest::class, 'json');
        $errors = $this->validator->validate($dto);

        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            throw new RuntimeException(implode("\n", $messages));
        }

        $existingUserEntity = $this->userEntityRepository->findOneByUsername($dto->username);

        return $existingUserEntity ?? PublicKeyCredentialUserEntity::create(
            $dto->username,
            $this->userEntityRepository->generateNextUserEntityId(),
            $dto->displayName
        );
    }
}
