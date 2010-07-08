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
namespace Ops\Auth;

class Result
{
	const FAILURE = 0;
	const FAILURE_IDENTITY_NOT_FOUND = -1;
	const FAILURE_IDENTITY_AMBIGUOUS = -2;
	const FAILURE_CREDENTIAL_INVALID = -3;
	const FAILURE_COMMUNICATION = -4;
	const FAILURE_UNCATEGORIZED = -5;
	const SUCCESS = 1;

	/**
	 * The authentication result code.
	 * @var int
	 */
	private $_code;

	/**
	 * The identity.
	 * @var mixed
	 */
	private $_identity;

	/**
	 * Creates a new authentication result.
	 * 
	 * @param int $code The authentication code.
	 * @param mixed $identity The identity to store
	 */
	public function __construct($code, $identity = null)
	{
		$this->_code = $code;
		$this->_identity = $identity;
	} // end __construct();

	/**
	 * Checks, if the result is valid (successful).
	 *
	 * @return boolean
	 */
	public function isValid()
	{
		return ($this->_code > 0);
	} // end isValid();

	/**
	 * Returns the authentication result code.
	 * @return int
	 */
	public function getCode()
	{
		return $this->_code;
	} // end getCode();

	/**
	 * Returns the user identity to store.
	 * 
	 */
	public function getIdentity()
	{
		return $this->_identity;
	} // end getIdentity();
} // end Result;