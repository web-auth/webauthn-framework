<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Guesser;

use function count;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialUserEntity;

final class RequestBodyUserEntityGuesser implements UserEntityGuesser
{
    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly PublicKeyCredentialUserEntityRepository $userEntityRepository
    ) {
    }

    public function findUserEntity(Request $request): PublicKeyCredentialUserEntity
    {
        $request->getContentType() === 'json' || throw InvalidDataException::create(
            $request->getContentType(),
            'Only JSON content type allowed'
        );
        $content = $request->getContent();
        is_string($content) || throw InvalidDataException::create($content, 'Invalid data');

        /** @var ServerPublicKeyCredentialCreationOptionsRequest $dto */
        $dto = $this->serializer->deserialize($content, ServerPublicKeyCredentialCreationOptionsRequest::class, 'json');
        $errors = $this->validator->validate($dto);

        if (count($errors) > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            throw InvalidDataException::create(null, implode("\n", $messages));
        }

        $existingUserEntity = $this->userEntityRepository->findOneByUsername($dto->username);

        return $existingUserEntity ?? PublicKeyCredentialUserEntity::create(
            $dto->username,
            $this->userEntityRepository->generateNextUserEntityId(),
            $dto->displayName
        );
    }
}
