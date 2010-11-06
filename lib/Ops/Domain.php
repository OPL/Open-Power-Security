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
namespace Ops;
use \Ops\Policy\Exception as Policy_Exception;

/**
 * The class represents a security domain, where we perform some actions.
 *
 * @author Tomasz Jędrzejewski
 * @copyright Invenzzia Group <http://www.invenzzia.org/> and contributors.
 * @license http://www.invenzzia.org/license/new-bsd New BSD License
 */
class Domain
{
	/**
	 * The security policy used by this domain.
	 * @var Policy
	 */
	private $_policy;

	/**
	 * The name of the domain.
	 * @var string
	 */
	private $_name;

	/**
	 * Creates the domain object.
	 *
	 * @param string $name The domain name.
	 */
	public function __construct($name)
	{
		$this->_name = $name;
	} // end __construct();

	/**
	 * Assigns a policy to the domain.
	 *
	 * @throws \Ops\Exception
	 * @param Policy $policy The new domain policy
	 */
	final public function setPolicy(Policy $policy)
	{
		$this->_policy = $policy;
	} // end setPolicy();

	/**
	 * Returns the current security policy.
	 *
	 * @return string
	 */
	final public function getPolicy()
	{
		return $this->_policy;
	} // end getPolicy();

	/**
	 * Returns the domain name.
	 * 
	 * @return string
	 */
	final public function getName()
	{
		return $this->_name;
	} // end getName();

	/**
	 * Verifies a security event by the domain policy. This is a screamy method,
	 * which means that denying a permission causes an exception.
	 *
	 * @param Event $event The event to verify.
	 * @return Event
	 */
	final public function verifyScream(Event $event)
	{
		if($this->_policy === null)
		{
			throw new Exception('Cannot verify the event '.$event->getName().' in domain '.$this->_name.': no policy is set.');
		}

		if($event->isAllowed() == Event::UNDEFINED)
		{
			$this->_policy->processEvent($event);
		}
		if($event->isAllowed() === Event::DENY)
		{
			throw new Policy_Exception('The permission to execute the event '.$event->getName().' has not been granted.');
		}
		return $event;
	} // end verifyScream();

	/**
	 * Verifies a security event by the domain policy. All the policy/authentication
	 * exceptions are captured by this method and interpreted as a denial. The verification
	 * result can be checked from the event object.
	 *
	 * @param Event $event The event to verify.
	 * @return Event
	 */
	final public function verify(Event $event)
	{
		if($this->_policy === null)
		{
			throw new Exception('Cannot verify the event '.$event->getName().' in domain '.$this->_name.': no policy is set.');
		}

		if($event->isAllowed() == Event::UNDEFINED)
		{
			try
			{
				$this->_policy->processEvent($event);
			}
			catch(Exception $exception)
			{
				$event->setAllowed(Event::DENY);
			}
		}
		return $event;
	} // end verify();
} // end Domain;