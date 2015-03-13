<?php
	putenv("INFORMIXDIR=/opt/informix64");
	//require "Configuracion.php";
	
	class Database{
	
		protected $confguracion = null;
		protected $connection	= null;
		protected $nonQueryStmt	= null;
		protected $queryStmt	= null;
		
		function __construct(/*$database_host, $database_dbname, $server, $service = 1526, $protocol = 'onsoctcp', $username, $password*/){
			try{
				$database_host 		= ""; 
				$database_dbname 	= "";
				$server				= ""; 
				$service 			= 1526; 
				$protocol 			= 'onsoctcp'; 
				$username 			= "";
				$password 			= "";
				if(func_num_args() == 2){
					/* se recibe como parametro la ruta al archivo de confirguarion y el ambiente */
					$params 			 = func_get_args();
					$ruta_configuracion  = $params[0];
					$ambiente 		 	 = $params[1];
					
					$this->configuracion = new Configuracion($ruta_configuracion, $ambiente);
				
					$database_host 		 = $this->configuracion->getDato("database.host");
					$database_dbname	 = $this->configuracion->getDato("database.dbname");
					$server		 		 = $this->configuracion->getDato("database.server");
					$service	 		 = $this->configuracion->getDato("database.service");
					$protocol	 		 = $this->configuracion->getDato("database.protocol");
					$username 			 = $this->configuracion->getDato("database.username");
					$password	 		 = $this->configuracion->getDato("database.password");
					
				}
				elseif(func_num_args() == 7){
					/* se reciben los parametros de conexion a la base de datos */
					$params 			 = func_get_args();
					$database_host 		 = $params[0];
					$database_dbname	 = $params[1];
					$server		 		 = $params[2];
					$service	 		 = $params[3];
					$protocol	 		 = $params[4];
					$username 			 = $params[5];
					$password	 		 = $params[6];
				}
				else{
					/* error */
					throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
				}				
				$connectionString = "informix:host=$database_host; service=$service;database=$database_dbname; server=$server; protocol=$protocol;EnableScrollableCursors=1, Autocommit=0";
				
				var_dump($connectionString);
				
				$this->connection = new PDO($connectionString, $username, $password);
				$this->connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
				$this->connection->setAttribute(PDO::ATTR_CASE, PDO::CASE_NATURAL);				
			}
			catch(PDOException $e){
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		function BeginTransaction(){
			if(!$this->connection->beginTransaction()){
				throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
			}
		}
		
		function CommitTransaction(){
			if(!$this->connection->commit()){
				throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
			}
		}
		
		function RollBackTransaction(){
			if(!$this->connection->rollBack()){
				throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
			}
		}
		
		function ExecuteNonQuery($nonQueryStatement, $parameters, $returnLastId = false){
			try{
				$this->nonQueryStmt = $this->connection->prepare($nonQueryStatement);
				$res = $this->nonQueryStmt->execute($parameters);
				
				if($returnLastId){
					return $this->connection->lastInsertId();
				}
				else{
					return $res;
				}
			}
			catch(PDOException $e){
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		function ExecuteLastNonQuery($parameters, $returnLastId = false){
			try{
				$res = $this->nonQueryStmt->execute($parameters);
				
				if($returnLastId){
					return $connection->lastInsertId();
				}
				else{
					return $res;
				}
			}
			catch(PDOException $e){
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		function ExecuteQuery($queryStatement, $parameters){
			try{
				$this->queryStmt = $this->connection->prepare($queryStatement);
				$this->queryStmt->execute($parameters);
				$res = $this->queryStmt->fetchAll(PDO::FETCH_OBJ);
				
				return $res;
			}
			catch(PDOException $e){
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		function ExecuteLastQuery($parameters){
			try{
				$this->queryStmt->execute($parameters);
				$res = $this->queryStmt->fetchAll(PDO::FETCH_OBJ);
				
				return $res;
			}
			catch(PDOException $e){
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
	}

?>
