<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Authentication;

use LogicException;
use function sprintf;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Webauthn\AuthenticatorResponse;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

final class WebauthnBadge extends UserBadge
{
    private bool $isResolved = false;

    private ?AuthenticatorResponse $authenticatorResponse = null;

    private ?PublicKeyCredentialOptions $publicKeyCredentialOptions = null;

    private ?PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity = null;

    private ?CredentialRecord $publicKeyCredentialSource = null;

    private ?UserInterface $user = null;

    /**
     * @var callable|null
     */
    private $userLoader;

    /**
     * @param array<string, mixed>|null $attributes
     */
    public function __construct(
        public readonly string $host,
        public readonly string $response,
        ?callable $userLoader = null,
        private readonly ?array $attributes = null,
        public bool $allowRegistration = false
    ) {
        parent::__construct($host, $userLoader, $attributes);
        $this->userLoader = $userLoader;
    }

    public function isResolved(): bool
    {
        return $this->isResolved;
    }

    public function getAuthenticatorResponse(): AuthenticatorResponse
    {
        if (! $this->isResolved || $this->authenticatorResponse === null) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->authenticatorResponse;
    }

    public function getPublicKeyCredentialOptions(): PublicKeyCredentialOptions
    {
        if (! $this->isResolved || $this->publicKeyCredentialOptions === null) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->publicKeyCredentialOptions;
    }

    public function getPublicKeyCredentialUserEntity(): PublicKeyCredentialUserEntity
    {
        if (! $this->isResolved || $this->publicKeyCredentialUserEntity === null) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->publicKeyCredentialUserEntity;
    }

    public function getPublicKeyCredentialSource(): CredentialRecord
    {
        if (! $this->isResolved || $this->publicKeyCredentialSource === null) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->publicKeyCredentialSource;
    }

    public function getUser(): UserInterface
    {
        if (! $this->isResolved || $this->user === null) {
            throw new LogicException('The badge is not resolved.');
        }
        return $this->user;
    }

    public function markResolved(
        AuthenticatorResponse $authenticatorResponse,
        PublicKeyCredentialOptions $publicKeyCredentialOptions,
        PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity,
        CredentialRecord $publicKeyCredentialSource,
    ): void {
        if ($this->userLoader === null) {
            throw new LogicException(sprintf(
                'No user loader is configured, did you forget to register the "%s" listener?',
                WebauthnBadgeListener::class
            ));
        }
        $this->authenticatorResponse = $authenticatorResponse;
        $this->publicKeyCredentialOptions = $publicKeyCredentialOptions;
        $this->publicKeyCredentialUserEntity = $publicKeyCredentialUserEntity;
        $this->publicKeyCredentialSource = $publicKeyCredentialSource;
        /** @var UserInterface|null $user */
        $user = ($this->userLoader)($publicKeyCredentialUserEntity->name, $this->attributes ?? []);
        if ($user === null) {
            $exception = new UserNotFoundException();
            $exception->setUserIdentifier($publicKeyCredentialSource->userHandle);

            throw $exception;
        }
        $this->user = $user;
        $this->isResolved = true;
    }

    public function setUserLoader(callable $userLoader): void
    {
        $this->userLoader = $userLoader;
    }

    public function getUserLoader(): ?callable
    {
        return $this->userLoader;
    }
}
