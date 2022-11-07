<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use const DIRECTORY_SEPARATOR;
use function file_get_contents;
use InvalidArgumentException;
use function is_array;
use RuntimeException;
use function sprintf;
use Webauthn\MetadataService\Statement\MetadataStatement;

final class FolderResourceMetadataService implements MetadataService
{
    private readonly string $rootPath;

    public function __construct(string $rootPath)
    {
        $this->rootPath = rtrim($rootPath, DIRECTORY_SEPARATOR);
        is_dir($this->rootPath) || throw new InvalidArgumentException('The given parameter is not a valid folder.');
        is_readable($this->rootPath) || throw new InvalidArgumentException(
            'The given parameter is not a valid folder.'
        );
    }

    public function list(): iterable
    {
        $files = glob($this->rootPath . DIRECTORY_SEPARATOR . '*');
        is_array($files) || throw new RuntimeException('Unable to read files.');
        foreach ($files as $file) {
            if (is_dir($file) || ! is_readable($file)) {
                continue;
            }

            yield basename($file);
        }
    }

    public function has(string $aaguid): bool
    {
        $filename = $this->rootPath . DIRECTORY_SEPARATOR . $aaguid;

        return is_file($filename) && is_readable($filename);
    }

    public function get(string $aaguid): MetadataStatement
    {
        $this->has($aaguid) || throw new InvalidArgumentException(sprintf(
            'The MDS with the AAGUID "%s" does not exist.',
            $aaguid
        ));
        $filename = $this->rootPath . DIRECTORY_SEPARATOR . $aaguid;
        $data = trim(file_get_contents($filename));
        $mds = MetadataStatement::createFromString($data);
        $mds->getAaguid() !== null || throw new RuntimeException('Invalid Metadata Statement.');

        return $mds;
    }
}
