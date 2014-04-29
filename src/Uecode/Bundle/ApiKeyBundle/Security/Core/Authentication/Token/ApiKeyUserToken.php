<?php

namespace Uecode\Bundle\ApiKeyBundle\Security\Core\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

/**
 * @author Aaron Scherer <aequasi@gmail.com>
 */
class ApiKeyUserToken extends UsernamePasswordToken
{
    /**
     * @var string
     */
    protected $discriminator;

    /**
     * @param string $user
     * @param string $apiKey
     * @param string $discriminator
     * @param string $providerKey
     * @param array|\Symfony\Component\Security\Core\Role\RoleInterface[] $roles
     */
    public function __construct($user, $apiKey, $discriminator, $providerKey, array $roles = array())
    {
        parent::__construct($user, $apiKey, $providerKey, $roles);

        $this->setAttribute('discriminator', $discriminator);
    }

    /**
     * @return string
     */
    public function getApiKey()
    {
        return $this->getCredentials();
    }

    /**
     * @return string
     */
    public function getDiscriminator()
    {
        return $this->getAttribute('discriminator');
    }

    /**
     * {@inheritdoc}
     */
    public function __toString()
    {
        $class = get_class($this);
        $class = substr($class, strrpos($class, '\\')+1);

        $roles = array();
        foreach ($this->getRoles() as $role) {
            $roles[] = $role->getRole();
        }

        return sprintf('%s(user="%s", authenticated=%s, discriminator=%s, roles="%s")', $class, $this->getUsername(), json_encode($this->isAuthenticated()), json_encode($this->getDiscriminator()), implode(', ', $roles));
    }
}
