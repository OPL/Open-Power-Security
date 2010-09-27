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
 * The class represents a generic security policy. You should extend this class
 * in order to implement the permission granting rules.
 *
 * @author Tomasz Jędrzejewski
 * @copyright Invenzzia Group <http://www.invenzzia.org/> and contributors.
 * @license http://www.invenzzia.org/license/new-bsd New BSD License
 */
class Policy
{
	/**
	 * The name of the policy.
	 * @var string
	 */
	private $_name;

	/**
	 * Creates the policy object.
	 *
	 * @param string $name The policy name.
	 */
	public function __construct($name)
	{
		$this->_name = $name;
	} // end __construct();

	/**
	 * Returns the policy name.
	 *
	 * @return string
	 */
	public function getName()
	{
		return $this->_name;
	} // end getName();

	/**
	 * Processes a security event. The default implementation redirects the
	 * processing to a method constructed from the event name. If the event
	 * is not supported, it is automatically denied.
	 *
	 * @param Event $event The event to process.
	 */
	public function processEvent(Event $event)
	{
		$methodName = preg_replace_callback('/\.([a-zA-Z0-9\_]){1}/', function($matches){
			return strtoupper($matches[1]);
		}, $event->getName()).'Event';

		if(method_exists($this, $methodName))
		{
			$this->$methodName($event);
		}
		else
		{
			$event->setAllowed(Event::DENY);
		}
	} // end processEvent();
} // end Policy;