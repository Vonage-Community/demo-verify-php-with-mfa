<?php

namespace Vonage\Security;

use SensitiveParameter;

class User implements \Serializable
{
    protected string $username;

    protected string $password;

    protected string $phone;

    protected ?string $secret;

    public function __construct(string $username, #[SensitiveParameter] string $password, string $phone) {
        $this->username = $username;
        $this->password = password_hash($password, PASSWORD_DEFAULT);
        $this->phone = $phone;
        $this->secret = null;
    }

    public function __get(string $name): string|null
    {
        return match ($name) {
            'username' => $this->username,
            'password' => $this->password,
            'phone' => $this->phone,
            'secret' => $this->secret ?? null,
            default => null,
        };
    }

    public function setSecret(string $secret): void
    {
        $this->secret = $secret;
    }


    public function __serialize(): array
    {
        $ret = [
            'username' => $this->username,
            'password' => $this->password,
            'phone' => $this->phone,
        ];

        if (isset($this->secret)) {
            $ret['secret'] = $this->secret;
        }

        return $ret;
    }

    public function serialize(): string
    {
        return json_encode($this->__serialize());
    }

    public function __unserialize(array $data): void
    {
        $this->username = $data['username'];
        $this->password = $data['password'];
        $this->phone = $data['phone'];

        if (isset($data['secret'])) {
            $this->secret = $data['secret'];
        }
    }

    public function unserialize(string $data): void
    {
        $this->__unserialize(json_decode($data, true));
    }
}