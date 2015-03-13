<?php
	putenv("INFORMIXDIR=/opt/informix64");

	class SessionHandler{

		private $idSession 	= null;
		private $basedatos 	= null;
		
		public function __construct($id = null) {
			if(!isset($id)){
				throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
			}
				
			$this->idSession = $id;			
		}
		public function getIdSession(){
			return $this->idSession;
		}
		public function set($variable = "", $valor = ""){
			if(!isset($variable) or empty($variable)){
				throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
			}
			$var = &$variable;
			$this->$var = $valor;
				
			return true;			
		}
		public function get($atributo){
			$var = &$atributo;
			if(!isset($this->$var)){
				throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
			}
			return $this->$var;
		}
	}
	
	class Session {
		
		private $SessionHandler		= null;
		private $idSession 			= null;
		private $basedatos 			= null;
		static private $instance 	= null;
		
		public function __construct() {
			
			try{
				
				$database_host 		= ""; 
				$database_dbname 	= "";
				$server				= ""; 
				$service 			= 1526; 
				$protocol 			= 'onsoctcp'; 
				$username 			= "";
				$password 			= "";
				if(func_num_args() == 3){
					/* se recibe como parametro la ruta al archivo de confirguarion y el ambiente */
					$params 			 = func_get_args();
					$ruta_configuracion  = $params[0];
					$ambiente 		 	 = $params[1];
					$id 		 	 	 = $params[2];
					
					$this->configuracion = new Configuracion($ruta_configuracion, $ambiente);
				
					$database_host 		 = $this->configuracion->getDato("database.host");
					$database_dbname	 = $this->configuracion->getDato("database.dbname");
					$server		 		 = $this->configuracion->getDato("database.server");
					$service	 		 = $this->configuracion->getDato("database.service");
					$protocol	 		 = $this->configuracion->getDato("database.protocol");
					$username 			 = $this->configuracion->getDato("database.username");
					$password	 		 = $this->configuracion->getDato("database.password");
					
				}
				elseif(func_num_args() == 8){
					echo "IFFFFFFFF\n";
					/* se reciben los parametros de conexion a la base de datos */
					$params 			 = func_get_args();
					$database_dbname	 = $params[0];
					$database_host		 = $params[1];
					$server		 		 = $params[2];
					$service	 		 = $params[3];
					$protocol	 		 = $params[4];
					$username 			 = $params[5];
					$password	 		 = $params[6];
					$id	 		 		 = $params[7];
					
					echo "$database_host, $database_dbname, $server, $service, $protocol, $username, $password, $id\n\n";
				}
				else{
					/* error */
					throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
				}
				
				/*
				$connectionString = "mysql:host=" . $dbHost . ";dbname=" . $dbName . ";";
				$this->basedatos = new PDO($connectionString, $username, $password);
				$this->basedatos->setAttribute(PDO::ATTR_AUTOCOMMIT, FALSE);
				$this->basedatos->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
				$this->basedatos->setAttribute(PDO::ATTR_CASE,PDO::CASE_NATURAL);
				*/
				
				echo "#####################\n";
				echo "$database_host, $database_dbname, $server, $service, $protocol, $username, $password, $id\n\n";
				echo "#####################\n";
				
				$connectionString = "informix:host=$database_host; service=$service;database=$database_dbname; server=$server; protocol=$protocol;EnableScrollableCursors=1, Autocommit=0";
				$this->basedatos = new PDO($connectionString, $username, $password);
				$this->basedatos->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
				$this->basedatos->setAttribute(PDO::ATTR_CASE, PDO::CASE_NATURAL);
				
				/*
				$mydb = new PDO("informix:host=$dbHost; service=$service;database=$dbName; server=$server; protocol=$protocol;EnableScrollableCursors=1, Autocommit=0", $dbUser, $dbPass);
				$mydb->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
				$mydb->setAttribute(PDO::ATTR_CASE,PDO::CASE_NATURAL);
				*/
				//$mydb = new PDO("mysql:host=" . $dbHost . ";dbname=" . $dbName . ";", $dbUser , $dbPass);
				//$mydb->setAttribute(PDO::ATTR_AUTOCOMMIT, FALSE);
				//$this->basedatos 	= $mydb;
								
				$this->SessionHandler = $this->getSessionHandler($id);				
			}
			catch(Exception $e){
				//throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		public function getSessionHandler($id = null){
			try{
				if(isset($id) and ($id != null)){
					$this->idSession	= $id;
					$consulta 			= ' SELECT a_session FROM sessions WHERE id = ? ';
					$smt 				= $this->basedatos->prepare( $consulta );
					if(!$smt){
						throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
					}
					if(!$smt->execute(array($this->idSession))){
						throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
					}
					$row 		= $smt->fetch(PDO::FETCH_OBJ);
					
					if(!isset($row->a_session) or ($row->a_session == "")){
						throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
					}
					
					$session 	= unserialize($row->a_session);
				}
				else{
					if(!isset($id)){
						$this->idSession = md5(uniqid('', true));
					}
					$session = new SessionHandler($this->idSession);
					
					$consulta 		=  ' INSERT INTO sessions (id, a_session) VALUES (?, ?) ';
					$smt 			= $this->basedatos->prepare( $consulta );
					
					if(!$smt){
						throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
					}
					
					$consulta_lock 	=  ' SET LOCK MODE TO WAIT 10 ';
					$smt_lock		= $this->basedatos->prepare( $consulta_lock );
					if(!$smt_lock->execute(array())){
						throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
					}
					
					$this->basedatos->beginTransaction();
					
					
					$serialized = serialize($session);
					if(!$smt->execute(array($this->idSession, $serialized))){
						$this->basedatos->rollBack();
						throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
					}
					$this->basedatos->commit();					
				}
				return $session;
			}
			catch(Exception $e){
				//throw new Exception($e->getMessage(), 100);
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		public function persistir(){
			try{
				$consulta 			= ' UPDATE sessions SET a_session = ? WHERE id = ? ';
				$smtUpdate 			= $this->basedatos->prepare( $consulta );
				if(!$smtUpdate){
					throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
				}
				$this->basedatos->beginTransaction();
				$session	= $this->SessionHandler;
				$id 		= $session->getIdSession();
				$serialized = serialize($session);
				if(!$smtUpdate->execute(array($serialized, $id))){
					$this->basedatos->rollBack();
					throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
				}
				$this->basedatos->commit();		
			}
			catch(Exception $e){
				//throw new Exception($e->getMessage(), 100);
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		public function set($atributo = "", $valor = ""){
			try{
				$res = $this->SessionHandler->set($atributo, $valor);
				if(!$res){
					throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
				}
				$this->persistir();				
			}
			catch(Exception $e){
				//throw new Exception($e->getMessage(), 100);
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		public function get($atributo = ""){
			try{
				return $this->SessionHandler->get($atributo);
			}
			catch(Exception $e){
				//throw new Exception($e->getMessage(), 100);
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		public function getIdSession(){
			try{
				if(!isset($this->idSession) or (empty($this->idSession))){
					throw new Exception("ERROR :: " . __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
				}
				return $this->idSession;
			}
			catch(Exception $e){
				//throw new Exception($e->getMessage(), 100);
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}		
	}
	
?>	
