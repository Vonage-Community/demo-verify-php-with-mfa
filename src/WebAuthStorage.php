<?php

namespace Vonage\Security;

use MadWizard\WebAuthn\Credential\CredentialId;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Credential\UserHandle;

class WebAuthStorage implements CredentialStoreInterface
{
    protected ?int $counter = 0;

    public function findCredential(CredentialId $credentialId): ?UserCredentialInterface
    {
        $userCredential = UserService::getUserCredential();
        if ($userCredential === null || serialize($userCredential->getCredentialId()) !== serialize($credentialId)) {
            return null;
        }

        return $userCredential;
    }

    public function getSignatureCounter(CredentialId $credentialId): ?int
    {
        return $this->counter;
    }

    public function updateSignatureCounter(CredentialId $credentialId, int $counter): void
    {
        $this->counter = $counter;
    }

    public function getUserCredentialIds(UserHandle $userHandle): array
    {
        $userCredential = UserService::getUserCredential();
        if ($userCredential === null || serialize($userCredential->getUserHandle()) !== serialize($userHandle)) {
            return [];
        }

        return [
            $userCredential->getCredentialId(),
        ];
    }
}