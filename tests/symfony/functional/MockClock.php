<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

final class MockClock implements ClockInterface
{
    private null|DateTimeImmutable $now = null;

    public function now(): DateTimeImmutable
    {
        return $this->now ?? new DateTimeImmutable();
    }

    public function set(DateTimeImmutable $date): void
    {
        $this->now = $date;
    }
}
