<?php
/**
 * LDAPAuth Class
 * 
 * @name ldapauth.class.php
 * @author Mattia - http://www.matriz.it
 * @version 1.1.0
 * @date July 20, 2017
 * @category PHP Class
 * @copyright (c) 2017 Mattia at Matriz.it (info@matriz.it)
 * @license MIT - http://opensource.org/licenses/mit-license.php
 * @example Visit http://www.matriz.it/projects/ldap-auth/ for more informations about this PHP class
 */

class LDAPAuth {
	/**
	 * Host a cui connettersi
	 * @private
	 * @var string
	 */
	private $host = 'localhost';
	
	/**
	 * Porta a cui connettersi
	 * @private
	 * @var integer
	 */
	private $port = 389;
	
	/**
	 * Dominio
	 * @private
	 * @var string
	 */
	private $domain = '';
	
	/**
	 * Username
	 * @private
	 * @var string
	 */
	private $username = '';
	
	/**
	 * Password
	 * @private
	 * @var string
	 */
	private $password = '';
	
	/**
	 * Stabilisce se si è connessi con un utente
	 * @private
	 * @var boolean
	 */
	private $is_binded = false;
	
	/**
	 * Connessione LDAP
	 * @private
	 * @var resource
	 */
	private $resource;
	
	/**
	 * Metodo chiamato alla distruzione dell'oggetto
	 * @public
	 */
	public function __destruct() {
		$this->disconnect();
	}
	
	/**
	 * Effettua la connessione
	 * @private
	 * @return boolean
	 */
	private function connect() {
		$res = $this->isConnected();
		if (!$res && function_exists('ldap_connect')) {
			$c = ldap_connect($this->host, $this->port);
			if ($c) {
				$this->resource = $c;
				$res = true;
			}
		}
		return $res;
	}
	
	/**
	 * Effettua la disconnessione
	 * @private
	 * @return boolean
	 */
	private function disconnect() {
		if ($this->isConnected()) {
			$res = ldap_close($this->resource);
		} else {
			$res = true;
		}
		if ($res) {
			$this->resource = null;
		}
		return $res;
	}
	
	/**
	 * Verifica che sia stata effettuata la connessione
	 * @public
	 * @return boolean
	 */
	public function isConnected() {
		return is_resource($this->resource);
	}
	
	/**
	 * Effettua il login
	 * @private
	 * @return boolean
	 */
	private function bind() {
		$res = $this->isBinded();
		if (!$res && $this->connect()) {
			$res = $this->is_binded = $this->checkLogin($this->username, $this->password);
		}
		return $res;
	}
	
	/**
	 * Verifica che sia stata effettuata la connessione
	 * @public
	 * @return boolean
	 */
	public function isBinded() {
		return $this->is_binded;
	}
	
	/**
	 * Assegna una configurazione
	 * @public
	 * @var string $type tipo di configurazione
	 * @var mixed $value valore della configurazione
	 * @return boolean
	 */
	public function setConfig($type, $value) {
		$res = false;
		$disconnect = false;
		switch (is_string($type) ? $type : '') {
			case 'host':
				if (is_string($value) && trim($value) != '') {
					$this->host = trim($value);
					$res = true;
					$disconnect = true;
				}
			break;
			case 'port':
				if (is_numeric($value)) {
					$this->port = (int)$value;
					$res = true;
					$disconnect = true;
				}
			break;
			case 'domain':
				if (is_string($value) && trim($value) != '') {
					$this->domain = trim($value);
					$res = true;
				}
			break;
			case 'username':
				if (is_string($value) && trim($value) != '') {
					$this->username = trim($value);
					$res = true;
				}
			break;
			case 'password':
				if (is_string($value) && trim($value) != '') {
					$this->password = trim($value);
					$res = true;
				}
			break;
		}
		if ($disconnect) {
			$this->disconnect();
		}
		return $res;
	}
	
	/**
	 * Assegna un'opzione
	 * @public
	 * @var mixed $option opzione
	 * @var mixed $value valore dell'opzione
	 * @return boolean
	 */
	public function setOption($option, $value) {
		return $this->connect() && ldap_set_option($this->resource, $option, $value);
	}
	
	/**
	 * Restituisce un'opzione
	 * @public
	 * @var mixed $option opzione
	 * @return mixed
	 */
	public function getOption($option) {
		$value = null;
		if ($this->connect() && !ldap_get_option($this->resource, $option, $value)) {
			$value = null;
		}
		return $value;
	}
	
	/**
	 * Controlla l'username e la password
	 * @public
	 * @var string $username username
	 * @var string $password password
	 * @return boolean
	 */
	public function checkLogin($username, $password) {
		$res = false;
		if (is_string($username) && trim($username) != '' && is_string($password) && trim($password) != '' && $this->connect()) {
			$res = @ldap_bind($this->resource, $this->escape($username, true).($this->domain == '' ? '' : '@'.$this->escape($this->domain, true)), $password);
		}
		return $res;
	}
	
	/**
	 * Restituisce i dati di un utente
	 * @public
	 * @var string $username username
	 * @return array
	 */
	public function getUserData($username) {
		$data = null;
		if (is_string($username) && trim($username) != '' && $this->connect()) {
			$this->bind();
			$dn = 'CN=Users';
			if ($this->domain != '') {
				$dn .= ',DC='.$this->escape($this->domain, true);
			}
			$dn .= ',DC=local';
			$results = @ldap_search($this->resource, $dn, '(samaccountname='.$this->escape($username, true).')');
			if ($results) {
				$entries = ldap_get_entries($this->resource, $results);
				if (is_array($entries) && isset($entries['count']) && is_numeric($entries['count']) && $entries['count'] > 0) {
					$data = array();
					foreach ($entries[0] as $k => $v) {
						if (is_array($v) && isset($v['count']) && is_numeric($v['count']) && $v['count'] > 0) {
							$data[$k] = $v[0];
						}
					}
				}
			}
		}
		return $data;
	}
	
	/**
	 * Restituisce l'ultimo errore
	 * @public
	 * @return string|null
	 */
	public function getError() {
		$err = null;
		if ($this->isConnected()) {
			$errno = ldap_errno($this->resource);
			if ($errno != 0) {
				$err = ldap_err2str($errno);
			}
		}
		return $err;
	}
	
	/**
	 * Fa l'escape di una stringa
	 * @private
	 * @var string $s stringa
	 * @var boolean $is_dn stabilisce se si tratta di un DN
	 * @return string
	 */
	private function escape($s, $is_dn = false) {
		if (is_scalar($s)) {
			$t = array();
			$chars = $is_dn ? array('\\', ',', '=', '+', '<', '>', ';', '"', '#') : array('\\', '*', '(', ')', chr(0));
			$counter = count($chars);
			for ($i = 0; $i < $counter; $i++) {
				$t[$chars[$i]] = '\\'.str_pad(dechex(ord($chars[$i])), 2, '0', STR_PAD_LEFT);
			}
			$s = strtr($s, $t);
		} else {
			$s = '';
		}
		return $s;
	}
}