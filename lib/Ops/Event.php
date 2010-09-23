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

/**
 * The class represents an event, which we want to check against user
 * permissions.
 *
 * @author Tomasz Jędrzejewski
 * @copyright Invenzzia Group <http://www.invenzzia.org/> and contributors.
 * @license http://www.invenzzia.org/license/new-bsd New BSD License
 */
class Event implements \ArrayAccess
{
	const ALLOW = true;
	const DENY = false;
	const UNDEFINED = null;

	/**
	 * The subject that tries to launch the event.
	 * @var object
	 */
	private $_subject;

	/**
	 * The event name.
	 * @var string
	 */
	private $_name;

	/**
	 * The event arguments.
	 * @var array
	 */
	private $_args;

	/**
	 * The current permission status.
	 * @var boolean
	 */
	private $_allowed = null;

	/**
	 * Creates the security event.
	 *
	 * @param object $subject The subject of the domain.
	 * @param string $name The event name.
	 * @param array $args The list of optional domain arguments.
	 */
	public function __construct($subject, $name, array $args = array())
	{
		$this->_subject = $subject;
		$this->_name = $name;
		$this->_args = $args;
	} // end __construct();

	/**
	 * Sets the new status of the event. Note that the status can
	 * be set only once. The further calls of this method will be
	 * ignored.
	 *
	 * @param boolean $result The new permission verification result.
	 */
	public function setAllowed($result)
	{
		if($this->_allowed === self::UNDEFINED)
		{
			$this->_allowed = (bool)$result;
		}
	} // end setAllowed();

	/**
	 * Checks if we are allowed to execute the event.
	 *
	 * @return boolean
	 */
	public function isAllowed()
	{
		return $this->_allowed;
	} // end isAllowed();

	/**
	 * Returns the subject associated with this event.
	 * @return object
	 */
	public function getSubject()
	{
		return $this->_subject;
	} // end getSubject();

	/**
	 * Returns the event name.
	 * @return string
	 */
	public function getName()
	{
		return $this->_name;
	} // end getName();

	/**
	 * Returns true if the parameter exists (implements the ArrayAccess interface).
	 *
	 * @param  string  $name  The parameter name
	 * @return boolean true if the parameter exists, false otherwise
	 */
	public function offsetExists($name)
	{
		return array_key_exists($name, $this->_args);
	} // end offsetExists();

	/**
	 * Returns a parameter value (implements the ArrayAccess interface).
	 *
	 * @param  string  $name  The parameter name
	 * @return mixed  The parameter value
	 */
	public function offsetGet($name)
	{
		if(!array_key_exists($name, $this->_args))
		{
			throw new \InvalidArgumentException(sprintf('The event "%s" has no "%s" parameter.', $this->name, $name));
		}

		return $this->_args[$name];
	} // end offsetGet();

	/**
	 * Sets a parameter (implements the ArrayAccess interface).
	 *
	 * @param string  $name   The parameter name
	 * @param mixed   $value  The parameter value
	 */
	public function offsetSet($name, $value)
	{
		$this->_args[$name] = $value;
	} // end offsetSet();

	/**
	 * Removes a parameter (implements the ArrayAccess interface).
	 *
	 * @param string $name    The parameter name
	 */
	public function offsetUnset($name)
	{
		unset($this->_args[$name]);
	} // end offsetUnset();
} // end Event;