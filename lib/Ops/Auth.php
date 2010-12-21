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
 * The authentication and credential manager. The interface is inspired by
 * Zend_Auth component from Zend Framework, but ported to namespaces. The
 * functional details of persisting the identity state are changed.
 *
 * @author Tomasz Jędrzejewski
 * @copyright Invenzzia Group <http://www.invenzzia.org/> and contributors.
 * @copyright Copyright (c) 2005-2010 Zend Technologies USA Inc. (http://www.zend.com)
 * @license http://www.invenzzia.org/license/new-bsd New BSD License
 */
class Auth
{
	/**
	 * The persistent identity storage.
	 * @var Auth\Storage
	 */
	private $_storage;

	/**
	 * The identity.
	 * @var mixed
	 */
	private $_identity = null;

	/**
	 * Was the identity loaded?
	 * @var boolean
	 */
	private $_identityLoaded = false;

	/**
	 * Sets the authentication storage.
	 * 
	 * @param Storage $storage
	 */
	public function setStorage(Auth\Storage $storage)
	{
		$this->_storage = $storage;
	} // end setStorage();

	public function getStorage()
	{
		if($this->_storage === null)
		{
			throw new Auth\Exception('The authentication storage is not available.');
		}
		return $this->_storage;
	} // end getStorage();

	public function authenticate(Auth\Credentials $credentials)
	{
		$result = $credentials->authenticate();

		if($this->hasIdentity())
		{
			$this->clearIdentity();
		}

		if($result->isValid())
		{
			$this->getStorage()->write($result->getIdentity());
		}

		return $result;
	} // end authenticate();

	public function getIdentity()
	{
		if(!$this->_identityLoaded)
		{
			$this->_identity = $this->getStorage()->read();
			$this->_identityLoaded = true;
		}

		return $this->_identity;
	} // end getIdentity();

	public function hasIdentity()
	{
		if(!$this->_identityLoaded)
		{
			$this->_identity = $this->getStorage()->read();
			$this->_identityLoaded = true;
		}

		return $this->_identity !== null;
	} // end hasIdentity();

	public function clearIdentity()
	{
		$this->getStorage()->clear();
	} // end clearIdentity();
} // end Auth;