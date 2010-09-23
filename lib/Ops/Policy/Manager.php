<?php
/*
 *  OPEN POWER LIBS <http://www.invenzzia.org>
 *
 * This file is subject to the new BSD license that is bundled
 * with this package in the file LICENSE. It is also available through
 * WWW at this URL: <http://www.invenzzia.org/license/new-bsd>
 *
 * Copyright (c) Invenzzia Group <http://www.invenzzia.org>
 * and other contributors. See website for details.
 */
namespace Ops\Policy;
use \Ops\Domain;
use \Ops\Exception as Ops_Exception;
use \Ops\Policy;
use \Ops\Event;

/**
 * The class manages the security policies.
 *
 * @author Tomasz Jędrzejewski
 * @copyright Invenzzia Group <http://www.invenzzia.org/> and contributors.
 * @license http://www.invenzzia.org/license/new-bsd New BSD License
 */
class Manager
{
	/**
	 * The authentication key that allows to perform certain actions on domains.
	 * @var string
	 */
	private $_key;

	/**
	 * The internal domain used to verify some security events related to the
	 * policy manager itself.
	 * @var Domain
	 */
	private $_internalDomain = null;

	/**
	 * The list of domains by object hash.
	 * @var array
	 */
	private $_domainsByHash = array();

	/**
	 * The list of domains by their names.
	 * @var array
	 */
	private $_domainsByNames = array();

	/**
	 * The available security policies.
	 * @var array
	 */
	private $_policies = array();

	/**
	 * Is the policy manager locked?
	 * @var boolean
	 */
	private $_locked = false;

	/**
	 * The arguments passed to the newly created policies.
	 * @var array
	 */
	private $_policyArgs = array();

	/**
	 * Creates the policy manager object.
	 */
	final public function __construct()
	{
		$this->_key = sha1(rand(0,100000).microtime(true));
	} // end __construct();

	/**
	 * Sets the policy arguments that will be injected into newly
	 * created policies.
	 *
	 * @param array $args The policy arguments.
	 */
	public function setPolicyArguments(array $args)
	{
		$this->_policyArgs = $args;
	} // end setPolicyArguments();

	/**
	 * Checks if the domain really belongs to this policy manager.
	 *
	 * @param Domain $domain The domain to verify.
	 * @return boolean
	 */
	final public function verifyDomain(Domain $domain)
	{
		return isset($this->_domains[spl_object_hash($domain)]);
	} // end checkKey();

	/**
	 * Adds a new policy to the system. The policy will be lazy-loaded
	 * on the first use.
	 *
	 * @param string $name The short name for the new policy.
	 * @param string $className The policy class name.
	 */
	public function addPolicy($name, $className)
	{
		$this->_policies[(string)$name] = (string) $className;
	} // addPolicy();

	/**
	 * Returns true, if the specified policy exists.
	 *
	 * @param string $name Policy name.
	 * @return boolean
	 */
	public function hasPolicy($name)
	{
		return isset($this->_policies[(string)$name]);
	} // end hasPolicy();

	/**
	 * Creates a security domain with the specified name and the optional
	 * initial policy. This method cannot be used, if the policy manager
	 * is locked. The newly created domain object is returned.
	 *
	 * @throws \Ops\Exception
	 * @param string $domainName The domain name.
	 * @param string $initialPolicy The name of the optional initial policy.
	 * @return Domain
	 */
	final public function createDomain($domainName, $initialPolicy = null)
	{
		if($this->_locked)
		{
			throw new Ops_Exception('Cannot create a domain: the policy manager is locked.');
		}

		$domain = new Domain($domainName, $this->_key);

		$this->_domainsByHash[spl_object_hash($domain)] = $domain;
		$this->_domainsByNames[$domainName] = $domain;

		if($initialPolicy !== null)
		{
			if(!isset($this->_policies[$initialPolicy]))
			{
				throw new Ops_Exception('Cannot set the domain policy: the policy "'.$initialPolicy.'" does not exist.');
			}
			$this->_domainsByNames[$domainName]->setPolicy($this->_key, $this->_getPolicy($initialPolicy));
		}

		return $domain;
	} // end createDomain();

	/**
	 * Sets the policy for the specified domain. This method cannot be used, if the policy manager
	 * is locked.
	 *
	 * @throws \Ops\Exception
	 * @param string $domainName Domain name
	 * @param string $policyName Policy name
	 */
	final public function setDomainPolicy($domainName, $policyName)
	{
		if($this->_locked)
		{
			throw new Ops_Exception('Cannot set the domain policy: the policy manager is locked.');
		}
		if(!isset($this->_domainsByNames[$domainName]))
		{
			throw new Ops_Exception('Cannot set the domain policy: the domain "'.$domainName.'" does not exist.');
		}
		$this->_domainsByNames[$domainName]->setPolicy($this->_key, $this->_getPolicy($policyName));
	} // end setDomainPolicy();

	/**
	 * Selects the internal domain used to verify the policy manager-related
	 * security events. This method cannot be used, if the policy manager
	 * is locked.
	 *
	 * @throws \Ops\Exception
	 * @param string $domainName Domain name.
	 */
	final public function setInternalDomain($domainName)
	{
		if($this->_locked)
		{
			throw new Ops_Exception('Cannot set the internal domain: the policy manager is locked.');
		}
		if(!isset($this->_domainsByNames[$domainName]))
		{
			throw new Ops_Exception('Cannot set the internal domain: the domain "'.$domainName.'" does not exist.');
		}

		$this->_internalDomain = $this->_domainsByNames[$domainName];
	} // end setInternalDomain();

	/**
	 * Returns the name of the internal domain.
	 *
	 * @return string
	 */
	public function getInternalDomainName()
	{
		if($this->_internalDomain === null)
		{
			return null;
		}
		return $this->_internalDomain->getName();
	} // end getInternalDomainName();

	/**
	 * Locks the policy manager.
	 */
	final public function lock()
	{
		$this->_locked = true;
	} // end lock();

	/**
	 * Unlocks the policy manager. The piece of code that attempts to unlock
	 * the policy manager, must show its security domain in order to be verified,
	 * if it can actually process the action. If the internal domain for the policy
	 * manager is not set, the manager is unlocked immediately.
	 *
	 * @throws \Ops\Exception
	 * @param Domain $currentDomain The domain that should allow us to unlock it.
	 */
	final public function unlock(Domain $currentDomain)
	{
		if($this->_internalDomain !== null)
		{
			if(!$this->verifyDomain($currentDomain))
			{
				throw new Exception('Cannot unlock the policy manager: attempting to use a hostile domain in the system!');
			}
			$this->_internalDomain->verifyScream(new Event($this, 'policyManager.unlock', array('domainName' => $currentDomain->getName())));
		}
		// If nobody screams, we can unlock the domain.
		$this->_locked = false;
	} // end unlock();

	/**
	 * Returns the domain object. The piece of code that attempts to obtain another
	 * domain object, must shows its current security domain in order to be verified,
	 * if it can actually get it. If the internal domain for the policy
	 * manager is not set, the manager is unlocked immediately.
	 *
	 * @throws \Ops\Exception
	 * @param Domain $currentDomain The current domain
	 * @param string $domainName The name of the domain we want to get.
	 * @return Domain
	 */
	final public function getDomain(Domain $currentDomain, $domainName)
	{
		if($this->_internalDomain !== null)
		{
			if(!$this->verifyDomain($currentDomain))
			{
				throw new Exception('Cannot get the domain: attempting to use a hostile domain in the system!');
			}
			$this->_internalDomain->verifyScream(new Event($this, 'policyManager.getDomain', array('domainName' => $currentDomain->getName(), 'requestedDomain' => $domainName)));
		}
		if(!isset($this->_domainsByNames[$domainName]))
		{
			throw new Ops_Exception('Cannot get the domain: the domain "'.$domainName.'" does not exist.');
		}
		// If nobody screams, we can unlock the domain.
		return $this->_domainsByNames[$domainName];
	} // end getDomain();

	/**
	 * Returns the name of the policy used by the domain.
	 *
	 * @throws \Ops\Exception
	 * @param string $domainName The domain name.
	 * @return string
	 */
	public function getDomainPolicy($domainName)
	{
		if(!isset($this->_domainsByNames[$domainName]))
		{
			throw new Ops_Exception('Cannot get the domain: the domain "'.$domainName.'" does not exist.');
		}
		return $this->_domainsByNames[$domainName]->getPolicyName();
	} // end getDomainPolicy();

	/**
	 * Checks if the domain with the specified name exists.
	 *
	 * @param string $name The domain name.
	 * @return boolean
	 */
	public function hasDomain($name)
	{
		return isset($this->_domainsByNames[$domainName]);
	} // end hasDomain();

	/**
	 * Performs the policy lazy-loading.
	 *
	 * @internal
	 * @throws \Ops\Exception
	 * @param string $policyName The name of the policy to get.
	 * @return Policy
	 */
	final private function _getPolicy($policyName)
	{
		if(!isset($this->_policies[$policyName]))
		{
			throw new Ops_Exception('Cannot set the domain policy: the policy "'.$policyName.'" does not exist.');
		}
		if(!is_object($this->_policies[$policyName]))
		{
			$className = $this->_policies[$policyName];
			$object = new $className($policyName);
			if(!$object instanceof Policy)
			{
				throw new Ops_Exception('The object of class '.$className.' is not a valid policy object.');
			}
			$object->initialize($this->_policyArgs);
			$this->_policies[$policyName] = $object;
		}
		return $this->_policies[$policyName];
	} // end _getPolicy();
} // end Manager;