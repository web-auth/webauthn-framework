<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService;

use JsonSerializable;

/**
 * @internal
 */
interface VerificationMethodDescriptorInterface extends JsonSerializable
{
    public const USER_VERIFY_PRESENCE = 0x00000001;
    public const USER_VERIFY_FINGERPRINT = 0x00000002;
    public const USER_VERIFY_PASSCODE = 0x00000004;
    public const USER_VERIFY_VOICE_PRINT = 0x00000008;
    public const USER_VERIFY_FACE_PRINT = 0x00000010;
    public const USER_VERIFY_LOCATION = 0x00000020;
    public const USER_VERIFY_EYE_PRINT = 0x00000040;
    public const USER_VERIFY_PATTERN = 0x00000080;
    public const USER_VERIFY_HAND_PRINT = 0x00000100;
    public const USER_VERIFY_NONE = 0x00000200;
    public const USER_VERIFY_ALL = 0x00000400;

    public function getUserVerification(): int;

    public function userPresence(): bool;

    public function fingerprint(): bool;

    public function passcode(): bool;

    public function voicePrint(): bool;

    public function facePrint(): bool;

    public function location(): bool;

    public function eyePrint(): bool;

    public function pattern(): bool;

    public function handprint(): bool;

    public function none(): bool;

    public function all(): bool;

    public function getCaDesc(): ?CodeAccuracyDescriptorInterface;

    public function getBaDesc(): ?BiometricAccuracyDescriptorInterface;

    public function getPaDesc(): ?PatternAccuracyDescriptorInterface;

    public function jsonSerialize(): array;
}
