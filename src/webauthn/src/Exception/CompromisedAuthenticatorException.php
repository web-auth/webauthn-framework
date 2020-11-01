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

namespace Webauthn\Exception;

use Throwable;
use Webauthn\MetadataService\StatusReport;

final class CompromisedAuthenticatorException extends WebauthnException
{
    /**
     * @var string
     */
    private $aaguid;

    /**
     * @var StatusReport
     */
    private $statusReport;

    public function __construct(string $aaguid, StatusReport $statusReport, string $message, ?Throwable $previous = null)
    {
        parent::__construct($message, $previous);
        $this->aaguid = $aaguid;
        $this->statusReport = $statusReport;
    }

    public function getAaguid(): string
    {
        return $this->aaguid;
    }

    public function getStatusReport(): StatusReport
    {
        return $this->statusReport;
    }

    public static function create(string $aaguid, StatusReport $statusReport, string $message, ?Throwable $previous = null): callable
    {
        return static function () use ($aaguid, $statusReport, $message, $previous) {
            return new self($aaguid, $statusReport, $message, $previous);
        };
    }
}
