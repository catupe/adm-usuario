<?php

	require "Configuracion.php";
	require "Database.php";
	require "Session.php";
	require "Mensajes.php";
	
	Class AdmUsuario{
	
		var $configuracion 	= null;
		var $basedatos		= null;
		var $session		= null;
		var $error 			= 0;
		
		public function AdmUsuario($ruta_configuracion = "", $ambiente = "desarrollo"){
			try{
				$this->ruta_configuracion 	= $ruta_configuracion;
				$this->ambiente		 		= $ambiente;
				$this->configuracion 		= new Configuracion($ruta_configuracion, $ambiente);	
				$this->basedatos 	 		= new Database($ruta_configuracion, $ambiente);
				$this->error				= 0;
				$this->basedatos->BeginTransaction();
				$this->mensaje 				= Mensajes::getInstance();				
			}
			catch(Exception $e){
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		function finalizar(){ 
			print "\n====SALGO DE ADM USUARIO ====\n";
			print "----".$this->error ."----\n";
			
			if($this->error == 0){
				// si no hubo error commiteo
				$this->basedatos->CommitTransaction();
			}
			else{
				// si hubo error rollback
				$this->basedatos->RollBackTransaction();
			}
		} 
		
		/**
		 * Login de usuario
		 * Entrada:
		 *	- login del usuario
		 *	- password del usuario
		 *	- ip del usuario
		 * Salida
		 *	- valido => valido = true sii el par login/password lo es
		 **/
		public function loguear($login = "", $pass = "", $ip = ""){
			try{
				$resValidar = $this->__validarUsuario($login, $pass, $ip);
				if($resValidar == 0){
					return array("valido" => $resValidar);
				}
				$resetear = "";
				$resUsuario = $this->getUsuario($login);
				if ($resUsuario->habilitado == 'S' and $resUsuario->activado == 'S'){
					$resetear  = $resUsuario->resetear;					
				}
				// crea una nueva sesion
				$this->cargarSesion(null);
				// guardo nombre de usuario en sesion
				$this->session->set("usuario", $login);
				
				// obtengo grupos a los que el usuario actual puede ver
				$resGruFunc 	= $this->__getGruposFuncion($login, "crear usuario");
				
				// obtengo las funciones del usuario
				$resFuncUsr 	= $this->__getFuncionesUsuario($login);
				
				$gruposTodos 	= $this->__getArbolGruposUsuario($login);
				
				if (count($gruposTodos) > 0){
					$salida["gruposTodos"] = $gruposTodos;
				}
				if (count($resGruFunc) > 0){
					$salida["grupos"] = $resGruFunc;	
				}
				if (count($resFuncUsr) > 0){
					$salida["funciones"] = $resFuncUsr;	
				}
				
				// obtengo los datos del perfil
				$resPerfil = $this->getPerfil($login); 
				$salida["perfil"] = $resPerfil;
				
				$salida["resetear"] = $resetear;
				$salida["session"]  = $this->session->getIdSession();
				$salida["valido"]	= 1;
				
				return $salida;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		/**
		 * Verifica que un par login/password sea valido
		 * Entrada:
		 *	- login del usuario
		 *	- password del usuario
		 *	- ip del usuario
		 * Salida
		 *	- valido => valido = true sii el par login/password lo es
		 **/
		private function __validarUsuario($login = "", $pass = "", $ip = ""){
			try{
				if($login == "" or $pass == ""){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_003', array());
					throw new Exception($mensaje, '003');
				}
				else{
					$pass_enc = sha1($pass);
					
					$consulta 	= ' SELECT id,today-fecha_cambio_password dias_clave FROM usuario 	'.
								  ' WHERE ((login = ?) and (password=?) and habilitado=1) 			';
					$res 		= $this->basedatos->ExecuteQuery($consulta, array($login, $pass_enc));
					
					if(!isset($res[0]->id)){
						$this->__marcarAccesoInvalido($login);
						return 0;
					}
					else{
						$idUsuario = $res[0]->id;
						$diasClave = $res[0]->dias_clave;
						$this->configuracion->getDato("database.host");
						if( $this->configuracion->getDato('tiempo_expiracion_contrasenia')!= 0 and
						    $this->configuracion->getDato('tiempo_expiracion_contrasenia') < $diasClave){

							$this->__modificarUsuario($idUsuario, array("resetear"=>'S'));

						}
						$consulta = ' SELECT count(*) cant 						'.
									' FROM ip_grupo ip, usr_grupo ug, usuario u '.
									' WHERE u.login = ? 						'.
									'  		and u.id=ug.usuario 				'.
									'  		and ug.grupo=ip.grupo 				';
						$res 	  = $this->basedatos->ExecuteQuery($consulta, array($login));
						if($res[0]->cant == 0){
							$res	= $this->__marcarAccesoValido($login);
							return 1;
						}
						else{
							$consulta = ' SELECT ip.ip 								'.
										' FROM ip_grupo ip, usr_grupo ug, usuario u '.
										' WHERE u.login = ? 						'.
										' 		and u.id=ug.usuario 				'.
										'		and ug.grupo=ip.grupo 				';
							$res 	  = $this->basedatos->ExecuteQuery($consulta, array($login));
							
							$coincide_ip 	= 0;
							$ip_origen 		= explode(".", $ip);
							foreach($res as $k => $v){
								$ip_valida 	= explode(".", $v->ip);
								$ok 		= 1;
								foreach($ip_valida as $k_ => $parte_ip){
									$parte_ip_orig = array_shift($ip_origen);
									if(($parte_ip != "*") and ($parte_ip != $parte_ip_orig)){
										$ok = 0;
									}
								}
								$coincide_ip = $ok;
							}
							if($coincide_ip > 0){
								$res	= $this->__marcarAccesoValido($login);
								return 1;
							}
							else{
								$res	= $this->__marcarAccesoInvalido($login);
								return 0;
							}
						}
					}
				}
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Incrementa el valor de los accesos invalidos para un usuario
		 *	Entrada:
		 *	 - login del usuario
		 *	Salida:
		 **/
		private function __marcarAccesoInvalido($login = ""){
			//$this->basedatos->BeginTransaction();
			try{
				if($login == ""){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_026', array('login'));
					throw new Exception($mensaje, '026');
				}
				else{
					$idUsuario = $this->__getIdUsuario($login);
					
					$consulta 	= ' UPDATE usuario SET accesos_invalidos=accesos_invalidos+1 WHERE login = ? ';
					$res 		= $this->basedatos->ExecuteNonQuery($consulta, array($login), false);
					
					$consulta	= ' SELECT accesos_invalidos FROM usuario WHERE login = ? ';
					$res 	  	= $this->basedatos->ExecuteQuery($consulta, array($login));
					
					if(isset($res[0]->accesos_invalidos)){
						$accesos_invalidos = $res[0]->accesos_invalidos;
						if($this->configuracion->getDato('max_accesos_invalidos') == $accesos_invalidos){
							$res = $this->__modificarUsuario($idUsuario, array("habilitado"=>'N'));
						}
					}
					//$this->basedatos->CommitTransaction();
				}
			}
			catch(Exception $e){
				$this->error = 1;
				//$this->basedatos->RollBackTransaction();
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Marca la cantidad de accesos invalidos en cero para un usuario
		 *	Entrada:
		 *	 - login del usuario
		 *	Salida:
		 **/
		private function __marcarAccesoValido($login = ""){
			//$this->basedatos->BeginTransaction();
			try{
				if($login == ""){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_026', array('login'));
					throw new Exception($mensaje, '026');
				}
				else{
					$consulta 	= ' UPDATE usuario SET accesos_invalidos = 0 WHERE login = ? ';
					$res 		= $this->basedatos->ExecuteNonQuery($consulta, array($login), false);
					//$this->basedatos->CommitTransaction();
				}
			}
			catch(Exception $e){
				$this->error = 1;
				//$this->basedatos->RollBackTransaction();
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}			
		}
		
		/**
		 *	Cambia los atributos especificados del usuario, estos pueden ser
		 *	 activado(S/N), habilitado(S/N),
		 *	 externo(S/N) y/o resetear(S/N).
		 *	Entrada:
		 *	 - id del usuario a modificar
		 *	 - atributos a modificar: hash que contiene pares atributo,valor del atributo.
		 **/
		private function __modificarUsuario($idUsuario = "", $atributos = array()){
			if($idUsuario == ""){
				$this->error = 1;
				$mensaje = $this->mensaje->getMensaje('ADM_USR_026', array('id usuario'));
				throw new Exception($mensaje, '026');
				//throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 200);
			}
			if(empty($atributos)){
				$this->error = 1;
				$mensaje = $this->mensaje->getMensaje('ADM_USR_026', array('atributos'));
				throw new Exception($mensaje, '026');
				//throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 200);
			}
			//$this->basedatos->BeginTransaction();
			try{
			
				$cont_consulta = "";
				#array de valores para la ejecucion de la consulta
				$array_valores = array();

				#campos con formato "S" o "N"
				$camposSN = array("activado","habilitado","externo","resetear");

				#para cada uno si, existe en el hash, verifico formato y lo agrego a la consulta
				foreach ($camposSN as $k => $elem){
					$seteado = 0;
					if (isset($atributos[$elem])){
						#verifico formato, si no es valido retorno excepcion
						if ($atributos[$elem] == 'S'){
							$seteado = 1;
						}elseif ($atributos[$elem] == 'N'){
							$seteado = 0;
						}else {
							$mensaje = $this->mensaje->getMensaje('ADM_USR_026', array($elem));
							throw new Exception($mensaje, '026');
							//throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 200);
						}

						#agrego campo y valor a la consulta
						if($cont_consulta != ""){
							$cont_consulta .= ",";
						}
						$cont_consulta .= " $elem = ? ";
						$array_valores[] = $seteado;
					}
				}
				$cont_consulta = preg_replace('/,$/', '', $cont_consulta);
				$array_valores[] = $idUsuario;

				$consulta = " UPDATE usuario SET $cont_consulta  WHERE id = ? ";
				$res 		= $this->basedatos->ExecuteNonQuery($consulta, $array_valores, false);
				//$this->basedatos->CommitTransaction();
			}
			catch(Exception $e){
				//$this->basedatos->RollBackTransaction();
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}

		/**
		 * Devuelve el id de un usuario
		 * Entrada:
		 *	- login del usuario
		 * Salida
		 * 	- id del usuario
		 **/
		private function __getIdUsuario($login = ""){
			try{
				if($login == ""){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_026', array('login'));
					throw new Exception($mensaje, '026');
				}
				else{
					$consulta 	= " SELECT id FROM usuario WHERE login = ? ";
					$res 	  	= $this->basedatos->ExecuteQuery($consulta, array($login));
					
					if(!isset($res[0]->id)){
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_015', array("usuario" => $login));
						throw new Exception($mensaje, "015");
					}
					else{
						return $res[0]->id;
					}
				}
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 * Obtener Usuario, devuelve en un hash los datos de un usuario
		 * Entrada:
		 *	- login del usuario
		 * Salida
		 * 	- ojeto con los campos:
		 *		dia_alta,hora_alta,activado(S/N),resetear(S/N),habilitado(S/N),externo(S/N)
		 **/
		public function getUsuario($login = ""){
			try{
				$idUsuario = $this->__getIdUsuario($login);
				
				$consulta 	= ' SELECT dia_alta,hora_alta, 	'.
							  '		   activado, 			'.
							  '		   resetear, 			'.
							  '		   habilitado, 			'.
							  '		   externo 				'.
							  '	FROM usuario 				'.
							  '	WHERE id = ? 				';
				$res 	  	= $this->basedatos->ExecuteQuery($consulta, array($idUsuario));
				
				$salida = $res[0];//new stdClass();
				if($res[0]->activado == 0){
					$salida->activado = 'N';
				}
				else{
					$salida->activado = 'S';
				}
				if($res[0]->resetear == 0){
					$salida->resetear = 'N';
				}
				else{
					$salida->resetear = 'S';
				}
				if($res[0]->habilitado == 0){
					$salida->habilitado = 'N';
				}
				else{
					$salida->habilitado = 'S';
				}
				if($res[0]->externo == 0){
					$salida->externo = 'N';
				}
				else{
					$salida->externo = 'S';
				}

				return $salida;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Devuelve el perfil de un usuario
		 *	 Entrada:
		 *	  - login del usuario
		 *	 Salida
		 *	  - perfil => objeto con los datos del perfil del usuario
		 *	  - si el usuario no tiene perfil asociado retorna null
		 **/
		public function getPerfil($login = ""){
			try{
				$idUsuario = $this->__getIdUsuario($login);
				
				$consulta = ' SELECT * FROM perfil WHERE id = ? ';
				$res 	  = $this->basedatos->ExecuteQuery($consulta, array($idUsuario));
				
				if(isset($res[0])){
					return $res[0];
				}
				else{
					return null;
				}
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}

		/**
		 *	Carga una sesion nueva si el parametro id es null
		 *	Entrada:
		 *	 - id de session o null en caso de sesion nueva
		 *	Salida:
		 **/
		public function cargarSesion($id = null){
			try{
				$s = new Session($this->ruta_configuracion, $this->ambiente, $id);
				$this->session = $s;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Dado un login y una funcion, devuelve sobre que grupos puede ejecutarla
		 *	Entrada:
		 *	 - login
		 *	 - funcion
		 * 	Salida
		 *	 - grupos => hash que tiene como llave el nombre de los grupos
		 **/
		private function __getGruposFuncion($login = "", $funcion = ""){
			try{
				$idUsuario 	= $this->__getIdUsuario($login);
				
				$funcion 	= $this->__getFuncion($funcion);
				
				$salida = array();
				
				if($funcion->valida_grupo != 'S'){
					$consulta = " SELECT nombre,descripcion FROM grupo ";
					$res 	  = $this->basedatos->ExecuteQuery($consulta, array());
					foreach( $res as $k => $v){
						$salida[]["nombre"] 	 = $v->nombre;
						$salida[]["descripcion"] = $v->descripcion;
					}
					
					return	$salida;
				}
				else{
					$marcados = array();
					$consulta =	' SELECT u.grupo hijo,g.nombre,g.descripcion 	'.
								' FROM usr_grupo u,funcionalidad f,grupo g 		'.
								' WHERE u.grupo=f.grupo 						'.
								'		AND g.id=u.grupo 						'.
								'		AND usuario = ?							'.
								'		AND funcion = ?							';
					$res 	  = $this->basedatos->ExecuteQuery($consulta, array($idUsuario, $funcion->id));
					
					$cons_grupos =  ' SELECT j.hijo,g.nombre, g.descripcion '.
									'	FROM jerarquia j,grupo g 			'.
									'	WHERE g.id = j.hijo 				'.
									'		  AND padre in (-1				';
					$seguir  = 1;
					$primera = 1;
					while($seguir){
						$seguir  = 0;
						$in		 = "";
						$valores = array();
						foreach($res as $k => $v){
							if(!isset($marcados[$v->hijo])){
								$in .= ",?";
								$valores[] = $v->hijo;
								if(!$primera){
									$marcados[$v->hijo] 		= 1;
									$salida[]["nombre"] 		= $v->nombre;
									$salida[]["descripcion"]	= $v->descripcion;
								}
								$seguir=1;
							}
						}
						if($seguir){
							$res 	  = $this->basedatos->ExecuteQuery($cons_grupos.$in.")", $valores);
						}
						$primera = 0;
					}

					return	$salida;
				}
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Devuelve todas las funciones a las que el usuario tiene acceso
		 *	Entrada:
		 *	 - login del usuario
		 *	Salida:
		 *	 - devuelve un array cuyas claves son los nombres de las funciones obtenidas
		 *	   y cuyos valores son objetos con los datos de las mismas.
		 **/
		public function getFuncionesUsuario($login = ""){
			try{
				if(true){
					$this->error = 1;
					throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 200);
				}
			
				#obtengo el id del usuario
				$idUsuario 	= $this->__getIdUsuario($login);
				
				$consulta 	= ' SELECT distinct ff.* 							'.
							  '	FROM usr_grupo ug, funcionalidad f, funcion ff 	'.
							  '	WHERE ug.usuario = ?							'.
							  '		  and ug.grupo = f.grupo 					'.
							  ' 	  and f.funcion = ff.id 					';
				$res 	  	= $this->basedatos->ExecuteQuery($consulta, array($idUsuario));
				
				$salida = array();
				foreach($res as $k => $v){
						$salida[$v->nombre] = $v;
				}
				return $salida;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Devuelve todos los grupos al que pertenece el usuario, mas los grupos hijos en su jerarquia
		 *	Entrada:
		 *	 - login del usuario
		 *	Salida:
		 *	 - devuelve un array cuyas claves son los nombres de los grupos obtenidos
		 *	   y cuyos valores son arrays con los datos de los mismos.
		 **/
		public function getArbolGruposUsr($login = ""){
			try{
				#obtengo el id del usuario
				$idUsuario 	= $this->__getIdUsuario($login);
				$salida		= array();
				$marcados = array();
				
				$consulta	= '	SELECT u.grupo hijo,g.nombre,g.descripcion 	'.
							  '	FROM usr_grupo u,grupo g 					'.
							  '	WHERE g.id = u.grupo 						'.
							  '		  AND usuario = ? 						';
				$res 	  	= $this->basedatos->ExecuteQuery($consulta, array($idUsuario));
				
				$cons_grupos = ' SELECT j.hijo,g.nombre, g.descripcion 	'.
							   ' FROM jerarquia j,grupo g 				'.
							   ' WHERE g.id = j.hijo 					'.
							   '	   AND padre in(-1 					';
				$seguir = 1;
				while($seguir){
					$seguir 	= 0;
					$in 		= "";
					$valores 	= array();
					foreach($res as $k => $v){
						if(!isset($marcados[$v->hijo])){
							$in 				.= ",?";
							$valores[] 			= $v->hijo;
							$marcados[$v->hijo] = 1;
							$salida[] 			= array("nombre" 		=> $v->nombre,
														"descripcion"	=> $v->descripcion);
							$seguir 			= 1;
						}
					}
					if($seguir){
						$res = $this->basedatos->ExecuteQuery($cons_grupos.$in.")", $valores);
					}
				}

				return	$salida;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Devuelve todas las funciones a las que el usuario tiene acceso
		 *	Entrada:
		 *	 - nombre del usuario
		 *	Salida:
		 *	 - devuelve en clave "funciones" un hash cuyas clavesson los nombres de las funciones obtenidas
		 *	   y cuyos valores son objetos con los datos de las mismas.
		 **/
		private function __getFuncionesUsuario($login = ""){
			try{
				#obtengo el id del usuario
				$idUsuario	= $this->__getIdUsuario($login);
				
				$consulta 	= ' SELECT distinct ff.* 							'.
							  '	FROM usr_grupo ug, funcionalidad f, funcion ff	'.
							  '	WHERE ug.usuario = ?							'.
							  '		  AND ug.grupo = f.grupo					'.
							  '		  AND f.funcion = ff.id						';
							  
				$res 	  	= $this->basedatos->ExecuteQuery($consulta, array($idUsuario));
				
				$funciones	= array();
				foreach($res as $k => $v){
					$funciones[$v->nombre]	=	$v;
				}
				return $funciones;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Devuelve un hash con el id, valida_usuario,valida_grupo
		 *	Entrada:
		 *	 - nombre de la funcion
		 *	Salida
		 *	 - hash con los campos	id
		 *							valida_usuario
		 *							valida_grupo
		 **/
		private function __getFuncion($funcion = ""){
			try{
				if($funcion == ""){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_026', array("parametro" => "nombre funcion"));
					throw new Exception($mensaje, '026');
				}
			
				$consulta	=	' SELECT id,valida_usuario,valida_grupo FROM funcion WHERE nombre = ? ';
				$resFuncion	= $this->basedatos->ExecuteQuery($consulta, array($funcion));

				if(!isset($resFuncion[0])){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('S000', array());
					throw new Exception($mensaje, 'S000');
					//throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 200);
				}
				
				return $resFuncion[0];
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Devuelve todos los grupos al que pertenece el usuario, mas los grupos hijos en su jerarquia
		 *	Entrada:
		 *	 - login del usuario
		 *	Salida:
		 *	 - devuelve en clave "grupos" un hash cuyas claves son los nombres de los grupos obtenidos
		 *		y cuyos valores son hashes con los datos de los mismos.
		 **/
		private function __getArbolGruposUsuario($login = ""){
			try{
				#obtengo el id del usuario
				$idUsuario = $this->__getIdUsuario($login);
				
				$consulta 		= 	'	SELECT u.grupo hijo,g.nombre,g.descripcion 	'.
									'	FROM usr_grupo u,grupo g					'.
									'	WHERE g.id = u.grupo						'.
									'		  AND usuario = ?						';
				$resGrupos		= $this->basedatos->ExecuteQuery($consulta, array($idUsuario));
				
				$cons_grupos 	=	' SELECT j.hijo,g.nombre, g.descripcion		'.
									' FROM jerarquia j,grupo g					'.
									' WHERE g.id = j.hijo						'.
									'		AND padre in (-1					';
				$seguir 	= 1;
				$marcados	= array();
				while($seguir){
					$seguir 	= 0;
					$in			= "";
					$valores 	= array();
					foreach($resGrupos as $k => $v){
						if(!isset($marcados[$v->hijo])){
							$in 				.= 	",?";
							$valores[] 			= 	$v->hijo;
							$marcados[$v->hijo]	=	1;
							$salida[] 			= array("nombre" 		=> $v->nombre,
														"descripcion"	=> $v->descripcion);
							$seguir				= 1;
						}
					}
					if($seguir){
						//$sth=$db->ejecutarSQL($cons_grupos.$in.")",@valores);
						$resGrupos = $this->basedatos->ExecuteQuery($cons_grupos.$in.")", $valores);
					}
				}

				return	$salida;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 * 	Si no se especifica grupos, devuelve todos los usuarios del sistema
		 *	Si no, devuelve la union de los usuarios de los grupos especificados
		 *	Entrada:
		 *	 - lista de grupos (puede ser vacia)
		 *	Salida:
		 *	 - devuelve en clave "usuarios" un hash cuyas claves
		 * 		son los login de los usuario obtenidos
		 *		y cuyos valores son hashes con los datos de los mismos.
		 **/
		public function listarUsuarios($idSesion = "", $grupos = array()){
			try{
				$where		 	=	' AND ( ';
				$consulta 	 	= 	'';
				$array_valores	= array();
				
				$this->cargarSesion($idSesion);
				//print "----------\n";
				//print "cantidad ==> ".count($grupos) . "\n";
				
				#si paso grupos verifico que existan
				if (count($grupos) > 0){
					#guardo grupos validos en el where
					foreach ($grupos as $k => $grupo){
						$idGrupo = $this->__getIdGrupo($grupo);
						$where .= ' (usr_grupo.grupo = ?) OR ';
						$array_valores[] = $idGrupo;
					}
					$where = preg_replace('/\s+OR\s+$/', "", $where);
					$where .= ' ) ';

					$consulta = " 	SELECT distinct usuario.id, 					".
								"		   usuario.login,							".
								"		   usuario.activado,						".
								"		   usuario.resetear,						".
								"		   usuario.habilitado						".
								"	FROM usuario, usr_grupo							".
								"	WHERE (usr_grupo.usuario = usuario.id) $where	";
				}
				else{
					$consulta = ' 	SELECT distinct usuario.id,					  	'.
								'		   usuario.login,                         	'.
								'		   usuario.activado,                      	'.
								'		   usuario.resetear,                       	'.
								'		   usuario.habilitado                      	'.
								'	FROM usuario 	                                ';
				}
				
				$res = $this->basedatos->ExecuteQuery($consulta, $array_valores);
				
				$usuarios = array();
				foreach ($res as $k => $v){
					$usuario = array();
					$usuario["id"] 			= $v->id;
					$usuario["login"] 		= $v->login;
					$usuario["activado"]	= $v->activado;
					$usuario["resetear"]	= $v->resetear;
					$usuario["habilitado"]	= $v->habilitado;
					$usuarios[$v->login]	= $usuario;
				}
				return $usuarios;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Devuelve el id de un grupo
		 *	Entrada:
		 *	 - nombre del grupo
		 *	Salida
		 *	 - id del grupo
		 **/
		private function __getIdGrupo($nombre = ""){
			try{
				if ($nombre == ""){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_026', array("parametro" => 'nombre grupo'));
					throw new Exception($mensaje, '026');
					//throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 200);
				}

				$consulta	=	' SELECT id FROM grupo where nombre = ? ';
				$res = $this->basedatos->ExecuteQuery($consulta, array($nombre));
				if(!isset($res[0]->id)){
					$this->error = 1;
					$mensaje =$this->mensaje->getMensaje('ADM_USR_017', array("grupo" => $nombre));
					throw new Exception($mensaje, '017');
				}

				return $res[0]->id;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Verifica si un usuario puede utilizar una funcion dada
		 * 	Entrada:
		 *	 - login del usuario
		 *	 - nombre de la funcion
		 *	 - (opcional) login del usuario afectado
		 *	 - (opcional) grupos afectados (array de nombre de grupos)
		 * 	Salida
		 * 	 - true sii el usuario puede ejecutar la funcion
		 **/
		public function validarFuncionalidad($login = "", $funcion = "", $login_destino = "", $grupos_a_validar = array()){
			try{
				$funcion	=	$this->__getFuncion($funcion);
				
				$idUsuario	=	$this->__getIdUsuario($login);
				
				//var_dump($funcion);
				
				if($funcion->valida_usuario != 'S' and $funcion->valida_grupo != 'S'){
					$consulta	=	'	select count(*) total				'.
									'	from usr_grupo ug, funcionalidad f	'.
									'	where 	ug.usuario = ?				'.
									'			and ug.grupo = f.grupo		'.
									'			and f.funcion = ?			';
					
					$res 	  = $this->basedatos->ExecuteQuery($consulta, array($idUsuario, $funcion->id));
					return $res[0]->total;

				}
				else{
					$idUsrDst	=	-1;
					if($funcion->valida_usuario == 'S'){
						$idUsrDst 	= 	$this->__getIdUsuario($login_destino);
					}
					$grupos_no_validados = array();
					if($funcion->valida_grupo == 'S'){
						if(!isset($grupos_a_validar) or (count($grupos_a_validar) == 0)){
							$this->error = 1;
							$mensaje = $this->mensaje->getMensaje('ADM_USR_058', array('login'));
							throw new Exception($mensaje, '058');
							//throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 200);
						}
						foreach ($grupos_a_validar as $k => $v){
							$idGrupo	=	$this->__getIdGrupo($v);
							$grupos_no_validados[$idGrupo] = 1;
						}
					}
					$consulta	=	'	SELECT grupo		'.
									'	FROM usr_grupo		'.
									'	WHERE usuario = ?	';
					$resGrupos 	= $this->basedatos->ExecuteQuery($consulta, array($idUsrDst));
					$grupos_dst = array(); #grupos a los que pertenece el usuario "afectado"
					
					foreach($resGrupos as $k => $v){
						$grupos_dst[$v->grupo]	=	1;
					}
					$consulta	=	'	SELECT g.grupo						'.
									'	FROM usr_grupo g, funcionalidad f	'.
									'	WHERE g.grupo = f.grupo				'.
									'	 	  AND g.usuario = ?				'.
									'	 	  AND f.funcion = ?				';
					
					$resGrupos 	= $this->basedatos->ExecuteQuery($consulta, array($idUsuario, $funcion->id));
					$grupos_ori	= array(); #grupos a los que pertenece el usuario que quiere utilizar la funcion
					foreach($resGrupos as $k => $v){
						$grupos_ori[] = $v->grupo;
					}
					$visitados 			= array();
					$usuario_validado	= 0;
					if ($funcion->valida_usuario != 'S'){
						$usuario_validado = 1;
					}
					while(1){
						$consulta	=	'	SELECT hijo			'.
										'	from jerarquia		'.
										'	where padre in (	';
						$valores 	= array();
						$prim		= 1;
						foreach($grupos_ori as $k => $v){
							$valores[] 		= $v;
							$visitados[$v]	= 1;
							if(!$prim){
								$consulta	.= ', ';
							}
							$prim			 = 0;
							$consulta		.= ' ? ';
						}
						if ($prim == 1){
							return 0;
						}
						$consulta	.= ' ) ';
						$grupos_ori	 = array();
						$res 	= $this->basedatos->ExecuteQuery($consulta, $valores);
					
						foreach($res as $k => $v){
							if($usuario_validado == 0){
								if (isset($grupos_dst[$v->hijo])){
									$usuario_validado	=	1; 
								}
							}
							if(isset($grupos_no_validados[$v->hijo])){
								unset($grupos_no_validados[$v->hijo]);
							}
							$largo	= 0;
							if(count($grupos_no_validados) > 0){ // cambie lo de arriba (foreach) por esto
								$largo = 1;
							}
							if($usuario_validado and ($largo == 0)){
								return 1;
							}
							if(!isset($visitados[$v->hijo])){
								$grupos_ori[] = $v->hijo;
							}
						}
					}
				}
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Devuelve los datos del usuario, generales, perfil y grupos
		 *	Entrada:
	 	 *	 - login del usuario que se desea obtener los datos
		 *	Salida:
		 *	 - datos del usuario
		 **/
		public function darDatosUsuario($login = ""){
			try{
				
				$datos 	= $this->getUsuario($login);
				
				$perfil = $this->getPerfil($login);
				
				$grupos = $this->getGruposUsr($login);
				
				return array("usuario"	=>	$datos,
							 "perfil"	=>	$perfil,
							 "grupos"	=>	$grupos);
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		} 
		
		/**
		 *	Devuelve todos los grupos al que pertenece el usuario
		 *	Entrada:
		 *	 - nombre del usuario
		 *	Salida:
		 *	 - devuelve en clave "grupos" un hash cuyas claves son los nombres de los grupos obtenidos
		 *	   y cuyos valores son hashes con los datos de los mismos.
		 **/
		public function getGruposUsr($login = ""){
			try{
				#obtengo el id del usuario
				$idUsuario	=	$this->__getIdUsuario($login);
				
				$consulta	=	'	SELECT distinct g.* 		'.
								'	FROM grupo g, usr_grupo ug	'.
								'	WHERE ug.grupo = g.id		'.
								'		  AND ug.usuario = ?	';
					
				$res 	= $this->basedatos->ExecuteQuery($consulta, array($idUsuario));
			
				$grupos = array();
				foreach($res as $k => $v){
					$grupos[$v->nombre]	= $v;
				}
				return $grupos;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		/**
		 *	Crea un nuevo usuario en la base de datos
		 * 	Entrada:
		 *	 - login del usuario
		 *	 - password del usuario
		 *	 - activado (S/N)
		 *	 - habilitado (S/N)
		 *	 - externo (S/N)
		 *	Salida:
		 *	 - id del nuevo usuario
		 **/
		private function __crearUsuario($login = "", $password = "", $activado = 'S', $habilitado = 'S', $externo = 'S'){
			try{
				
				if ((!isset($password)) or (!isset($login)) or ($password == "") or ($login == "")){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_003', array('login'));
					throw new Exception($mensaje, '003');
					//throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 200);
				}
				#Almaceno un SHA1 de la password
				$password = sha1($password);

				#Verifica que el nombre de usuario sea unico
				$consulta 	= ' SELECT id FROM usuario WHERE login = ? ';
				$res 		= $this->basedatos->ExecuteQuery($consulta, array($login));
				
				if (isset($res[0]->id)){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_005', array('usuario' => $login));
					throw new Exception($mensaje, '005');
				}
				$valores		= array();
				$valores[] 		= $login;
				$valores[] 		= $password;
				$valores_		= "";
				$cont_consulta 	= "";

				#si activado o habilitado estan definidos deben ser validos
				if (isset($activado)){
					if ($activado == 'S'){
						$activado	=	1;
					}elseif ($activado == 'N'){
						$activado	=	0;
					}else {
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_023', array());
						throw new Exception($mensaje, '023');						
					}
					$cont_consulta 	= ",activado";
					$valores_		= ",?";
					$valores[]		= $activado;
				}

				if (isset($habilitado)){
					if ($habilitado == 'S'){
						$habilitado	=	1;
					}elseif ($habilitado == 'N'){
						$habilitado	=	0;
					}else {
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_024', array());
						throw new Exception($mensaje, '024');						
					}
					$cont_consulta  .= ",habilitado";
					$valores_		.= ",?";
					$valores[] 		= $habilitado;

				}
				if (isset($externo)){
					if ($externo == 'S'){
						$externo	=	1;
					}elseif ($externo == 'N'){
						$externo	=	0;
					}else {
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_089', array());
						throw new Exception($mensaje, '089');
					}
					$cont_consulta 	.= ",externo";
					$valores_		.= ",?";
					$valores[] 		= $externo;

				}

				//$new_id	= $self->_getNextNumerador("usuario"); poner los ids serial en las tablas -- ALTER TABLE usuario MODIFY id serial

				$consulta =	"	INSERT INTO usuario					".
							"	(login,password $cont_consulta )	".
							"	VALUES (?, ? $valores_ )			";	
				
				$idNew 	  = $this->basedatos->ExecuteNonQuery($consulta, $valores, true);
				
				return $idNew;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		#getIdUsuario
		#Devuelve todas las ip del grupo
		#Entrada: 
		#	-nombre del grupo
		#Salida:
		#	- devuelve un hash donde la clave es "ips" y los elementos 
		#	  son los ip del grupo.
		public function getIpGrupo ($grupo) {
			try{
				$idGrupo =	$this->__getIdGrupo($grupo); 
				$consulta 	= 'SELECT ip FROM ip_grupo WHERE grupo=?';
				$res 		= $this->basedatos->ExecuteQuery($consulta, array($idGrupo));
				$ips = array();
				foreach ($res as $row) {
					$ips[] = $row->ip;
				}
				return $ips;
				//$sth->finish();
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}

		
		/**
		 * 	Crea un perfil para un usuario
		 *	Entrada:
		 *	- login del usuario
		 *	- array con la forma columna => valor
		 *	Salida:
		 *	- id del nuevo perfil insertado
		 **/
		public function __crearPerfilUsuario($login = "", $datos = array()){
			try{
				#obtengo el id del usuario
				$idUsuario = $this->__getIdUsuario($login);
				
				#verifico q no exista un perfil para ese usuario
				$consulta = ' 	SELECT count(*) total	'.
							'	FROM perfil				'.
							'	WHERE id = ?			';
				$res 	  = $this->basedatos->ExecuteQuery($consulta, array($idUsuario));
				
				if($res[0]->total > 0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_013', array('usuario' => $login));
					throw new Exception($mensaje, '005');
				}
			
				#armo el insert
				$columnas	= "";
				$espacios	= "";
				$array_vals	= array($idUsuario);
				//foreach $cols (keys %{$hash}){
				foreach($datos as $cols => $v){
					$columnas	.=	", " . $cols;
					$espacios	.=	", ?";
					$array_vals[] = $v;
				}
		
				$insert = " INSERT INTO perfil	(id $columnas) VALUES (? $espacios) ";
				$idNew 	  = $this->basedatos->ExecuteNonQuery($insert, $array_vals, true);
				
				return $idNew;
				
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	Asigna un usuario a un grupo.
		 *	El usuario y el grupo deben ser creados previamente.
		 *	Entrada:
		 *	- nombre del usuario
		 *	- nombre del grupo
		 **/
		private function __asignarGrupo($login = "", $grupo = ""){
			try{
				
				$idUsuario 	= $this->__getIdUsuario($login);

				$idGrupo 	= $this->__getIdGrupo($grupo);
				
				$consulta	= ' SELECT count(*) total 	'.
							  '	FROM usr_grupo			'.
							  '	WHERE grupo = ?			'.
							  '		  and usuario = ?	';
				$res 	 	= $this->basedatos->ExecuteQuery($consulta, array($idGrupo, $idUsuario));
								
				if ($res[0]->total > 0){
					$mensaje = $this->mensaje->getMensaje('ADM_USR_018', array('usuario' => $login,
																			   'grupo'	 => $grupo));
					$this->error = 1;
					throw new Exception($mensaje, '018'); 						
				}
				
				$insert		= ' INSERT INTO usr_grupo (grupo,usuario) VALUES (?,?) ';
				$idNew 	 	= $this->basedatos->ExecuteNonQuery($insert, array($idGrupo, $idUsuario), true);
				
				return $idNew;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		/**
		 *	Crea el usuario y da de alta el perfil
		 *	Entrada:
		 *	- login
		 *	- password
		 *	- activado
		 *	- habilitado
		 *	- externo
		 *	- perfil
		 *	- grupos
		 *	Salida:
		 *	- id del nuevo usuario
		 **/
		public function altaUsuario($login = "", $password = "", $activado = "", $habilitado = "", $externo = "", $perfil = array(), $grupos = array()){
			try{
				
				$idUsuario = $this->__crearUsuario($login,$password,$activado,$habilitado,$externo);

				if(count($perfil) > 0){// tiene datos de perfil
					$resPerfil = $this->__crearPerfilUsuario($login, $perfil);
				}
				
				foreach ($grupos as $k => $g){
					$res   = $this->__asignarGrupo($login, $g);					
				}
				return $idUsuario;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		/** Le asigna al grupo de nombre "$nom_grupo" la IP "$ip_nueva"
		* Entrada: 
		*	- nombre del grupo e IP a asignar
		* Salida
		* 	- id del nuevo registro en la tabla ip_grupo
		**/
		public function agregarIPgrupo($nom_grupo,$ip_nueva){
			try{
				if ((!isset($nom_grupo)) or ($nom_grupo == "")){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_019', array());
					throw new Exception($mensaje, '019');
				}else{
					if ((!isset($ip_nueva)) or ($ip_nueva == "")){
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_085', array());
						throw new Exception($mensaje, '085');
					}
				}
				$idGrupo =	$this->__getIdGrupo($nom_grupo); 
				$consulta 	= 'SELECT * FROM ip_grupo WHERE (grupo = ?) and (ip = ?)';
				$res 		= $this->basedatos->ExecuteQuery($consulta, array($idGrupo,$ip_nueva));
				if(isset($res[0]->id)){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_088', array()); 
					throw new Exception($mensaje, "088");
				}else{
					$consulta   = 'INSERT INTO ip_grupo (ip,grupo) VALUES (?,?)';	
					$idNew 	    = $this->basedatos->ExecuteNonQuery($consulta, array($ip_nueva, $idGrupo), true);
					return $idNew;
				}
			}catch(Exeption $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		/** Le elimina al grupo de nombre "$nom_grupo" la IP "$ip_eliminar"
		* Entrada: 
		*	- nombre del grupo e IP a eliminar
		* Salida
		* 	- 
		**/
		public function eliminarIPgrupo($nom_grupo, $ip_eliminar){
			try{
				$idGrupo =	$this->__getIdGrupo($nom_grupo);
				$consulta 	= 'SELECT * FROM ip_grupo WHERE grupo=? and ip=?';
				$res 		= $this->basedatos->ExecuteQuery($consulta, array($idGrupo,$ip_eliminar));
				if(!isset($res[0]->id)){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_086', array());
					throw new Exception($mensaje, "086");
				}else{
					$consulta 	= 'Delete FROM ip_grupo WHERE grupo=? and ip=?';
					$res 		= $this->basedatos->ExecuteNonQuery($consulta, array($idGrupo,$ip_eliminar));
				}	
			}catch(Exeption $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		# Devuelve el subgrafo de la relacion jerarquica a partir de un grupo
		# Entrada:
		#	- nombre del grupo
		# Salida
		# 	- arreglo de la forma "nombre grupo"=> arreglo de hijos del grupo
		
		public function getSubgrafoJerarquia($grupo){
			try{
				$idGrupo = $this->__getIdGrupo($grupo); // Obtengo el id del grupo
				$marcados = array();
				$recorrida = array();
				$mapeos = array();
				$mapeos[$idGrupo] = $grupo;
				$recorrida[] = $idGrupo;
				$recorrida[] = $idGrupo;
				$salida = array();
				$consulta_recorrida = 'SELECT distinct g.nombre,g.id from jerarquia j, grupo g where padre = ? and j.hijo = g.id';
				while ($actual = next($recorrida)){
					unset($recorrida[0]); // Esto elimina el primer elemento del array
					if(!isset($marcados[$actual])){ // Si no se encuentra en marcados
						$marcados[$actual] = 1;
						$res = $this->basedatos->ExecuteQuery($consulta_recorrida, array($actual)); // Obtengo los hijos
						$hijos = array();
						foreach ($res as $row) {
							$nombre = $row->nombre; // Obtengo el nombre
							$id = $row->id; // Obtengo el id
							// Sustituyo espacios por [[:space:]]  $nombre =~ s/ \s / \[ \[ : space : \] \] /g;
							$mapeos[$id] = $nombre; // Lo agrego a mapeos
							$recorrida[] = $id; // Lo agrego a recorrida
							$hijos[$nombre] = "A"; // Lo agrego a hijos
						}
						$salida[$mapeos[$actual]] = $hijos;
					}
				}
				return $salida;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		
		}
		
		/**
		 *	elimina un usuario de la base de datos, junto con sus asociaciones a grupos y perfil
		 *	Entrada:
		 *	- login del usuario
		 **/
		public function eliminarUsuario($login = ""){
			try{
				$idUsuario = $this->__getIdUsuario($login);
		
				if($login == "root"){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_057', array());
					throw new Exception($mensaje, '057');
				}
		
				#Elimina el usuario del grupo
				$consulta = ' DELETE FROM usr_grupo WHERE usuario = ? ';
						$res = $this->basedatos->ExecuteNonQuery($consulta, array($idUsuario));
		
						#Elimina el perfil del usuario si existe
						$consulta = ' DELETE FROM perfil WHERE id = ? ';
				$res = $this->basedatos->ExecuteNonQuery($consulta, array($idUsuario));
		
						#Elimina el usuario
						$consulta = ' DELETE FROM usuario WHERE id = ? ';
				$res = $this->basedatos->ExecuteNonQuery($consulta, array($idUsuario));
		
			}
			catch(Exception $e){
			$this->error = 1;
			throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 * modifica el password de un usuario
		 * Entrada:
		 *	- login del usuario
		 *	- password actual del usuario
		 *	- nueva password del usuario
		 **/
		public function modificarPassword($login = "", $password = "", $nueva_pass = ""){
			try{
				if (!isset($login) or !isset($password) or !isset($nueva_pass)
						or ($login == "") or ($password == "") or ($nueva_pass == "")){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_049', array());
					throw new Exception($mensaje, '049');
				}
				$formato_pwd = $this->configuracion->getDato('formato_pwd');
				if(!preg_match('/' . $formato_pwd . '/', $nueva_pass)){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_087', array());
				}
				$password 	= sha1($password);
				$nueva_pass = sha1($nueva_pass);
		
				#verifico si existen usuario y clave
				$consulta = ' SELECT * FROM usuario WHERE login = ? AND password = ? ';
				$res = $this->basedatos->ExecuteQuery($consulta, array($login, $password));
		
				if (!isset($res[0]->login)){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_048', array());
					throw new Exception($mensaje, '048');
				}
		
				$consulta = ' UPDATE usuario											 	'.
							' SET password = ?,resetear = 0, fecha_cambio_password=today	'.
							' WHERE login = ? 												';
				$res = $this->basedatos->ExecuteNonQuery($consulta, array($nueva_pass, $login));
		
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 *	genera un password para el usuario, se lo asigna, y lo retorna
		 *	Entrada:
		 *	- login del usuario
		 *	- largo del nuevo password
		 *	Salida:
		 *	- password => nuevo password del usuario
		 **/
		public function resetearPasswd($login = "", $largo = ""){
			try{
				$idUsario = $this->__getIdUsuario($login);
				if (!isset($largo) or $largo == ""){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_050', array());
					throw new Exception($mensaje, '050');
				}
				$password = $this->generarPwd($largo);
		
				#sustituyo el password
				$consulta = ' update usuario					'.
							'  set password = ?, resetear = 1	'.
							'  where id= ?						';
				
				$res = $this->basedatos->ExecuteNonQuery($consulta, array(sha1($password), $idUsario));

				return $password;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		#Devuelve todas las funciones del grupo
		#Entrada: 
		#	-nombre del grupo
		#Salida:
		#	- devuelve un arreglo cuyas claves
		# 	son los nombres de las funciones obtenidas 
		#	y cuyos valores son arreglos con los datos de las mismas.

		public function getFuncionesGrupo($grupo){
			try{
				#obtengo el id del grupo
				$id = $this->__getIdGrupo($grupo);
				$consulta = 'select distinct ff.* from funcionalidad f, funcion ff where f.funcion=ff.id and f.grupo=?';
				$res = $this->basedatos->ExecuteQuery($consulta, array($id));
				$funciones = array();
				foreach ($res as $row) {
					$nombre = $row->nombre; // Obtengo el nombre de la funcion
					$funciones[$nombre] = $row;
				}
				return $funciones;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		# dado un login y un grupo, indica que funciones
		# puedo ejecutar sobre el
		# Entrada:
		#	- login del usuario
		#	- nombre del grupo 
		#Salida:
		#	- devuelve en clave "funciones" un hash cuyas claves
		# 	son los nombres de las funciones obtenidas 
		#	y cuyos valores son hashes con los datos de las mismas.
		
		public function getFuncionesSobreGrupo($login,$grupo){
			try{
				$grupos_usuario = $this->getGruposUsr($login); // Grupos a los que pertenece el usuario 
				$idGrupo = $this->__getIdGrupo($grupo); // Obtengo el id del grupo pasado como parametro
				$salida = array(); // Array para guardar la salida de la funcion
				$ids_grupos_uduario = array(); // Ids de los grupos del usuario
				foreach ($grupos_usuario as $nombre => $datos){ // Guardo en el array id->nombre de cada grupo
					$id   = $this->__getIdGrupo($nombre);		
					$ids_grupos_usuario[$id] = $nombre;
				}
				$recorrida = array(); // Array de grupos a recorrer
				$marcados = array(); // Array de grupos que ya se recorrieron
				$recorrida[] = $idGrupo; // Agrego el id del grupo pasado como parametro al arreglo de recorrida
				$consulta = "select padre from jerarquia where hijo = ?"; // Obtiene los padres del grupo pasado como parametro
				while( $actual = array_shift($recorrida) ){ // Recorro el arreglo de recorrida
					if(!isset($marcados[$actual])){ // Si no se encuentra marcado el grupo
						$marcados[$actual] = 1; // Marco el grupo
						$padres = $this->basedatos->ExecuteQuery($consulta, array($actual)); // Obtengo los padres
						foreach ($padres as $row) { // Recorro el conjunto de padres del grupo actual
							$padre = $row->padre; // Obtengo el Id del padre
							$recorrida[] = $padre; // Agrego el padre al arreglo de recorrida
							if(isset($ids_grupos_usuario[$padre])){ // Si el id del padre pertenece a los ids de los grupos a los cuales pertenece el usuario
								$fun = $this->getFuncionesGrupo($ids_grupos_usuario[$padre]); //Obtengo las funciones del grupo padre
								foreach ($fun as $nombre_funcion => $datos){ // Agrego los nombres de las funciones al array de salida
									$salida[$nombre_funcion] = 1;
								}
							}
						} 
					}
				}
				return $salida; // Retorno las funciones
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		#eliminarJerarquia
		#Elimina una jerarquia dada.
		#Entrada:
		#	- nombre del grupo padre
		#	- nombre del grupo hijo
		public function eliminarJerarquia($padre,$hijo){
			try{
				if(strcmp($padre, "root") == 0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_055', array());
					throw new Exception($mensaje, "055");
				}
				$idPadre = $this->__getIdGrupo($padre);
				$idHijo = $this->__getIdGrupo($hijo);
				$consulta= "select count(*) total from jerarquia where padre=? and hijo=?";
				$res = $this->basedatos->ExecuteQuery($consulta, array($idPadre,$idHijo));
				if(count($res) == 0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_047', array());
					throw new Exception($mensaje, "047");
				}
				$consulta = "delete from jerarquia where padre=? and hijo=?";
				$res 	  = $this->basedatos->ExecuteNonQuery($consulta, array($idPadre,$idHijo));
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		# Valida si se pueden eliminar ciertos hijos de un grupo
		# segun las reglas de jerarquia
		# Entrada:
		#	-login del usuario
		#	-nombre del grupo
		#	-array de hijos del grupo
		# Salida:
		#	- si es valida la operacion, valido=1
		#	- sino valido=0, y en "msg" el porque no es valido.
		public function validarEliminaHijosGrupo($login,$grupo,$hijos){
			try{
				$funciones_grupos = array();
				foreach ($hijos as $hijo) {
					$funciones = $this->getFuncionesSobreGrupo($login,$hijo);
					$funciones_grupos[$hijo] = $funciones;
				}
				foreach ($hijos as $hijo) {
					$res = $this->eliminarJerarquia($grupo,$hijo);
				}
				$valido=1;
				$funcion_falla;
				$hijo_falla;
				foreach ($hijos as $hijo) {
					$funciones = $this->getFuncionesSobreGrupo($login,$hijo);
					$funciones_sobre_hijo = $funciones_grupos[$hijo];
					foreach ($funciones_sobre_hijo as $funcion => $datos){
						if(!isset($funciones[$funcion])){
							$valido = 0;
							$hijo_falla = $hijo;
							$funcion_falla = $funcion;
							$ultimo = end($funciones_sobre_hijo);
						}
					}
					if($valido==0){
						$ultimo = end($hijos);
					}
				}
				foreach ($hijos as $hijo) {
					$res = $this->agregarJerarquia($grupo,$hijo);
				}
				if($valido==1){
					return array("valido"=>$valido);
				}else{
					return array("valido"=>$valido,"msg"=>"La funcion ".$funcion_falla." dejaria de ser aplicable al grupo ".$hijo_falla." por parte del usuario.");
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		#agregarJerarquia
		#Agrega una jerarquia.
		#Entrada:
		#	- nombre del grupo padre
		#	- nombre del grupo hijo
		public function agregarJerarquia($padre,$hijo){
			$idPadre = $this->__getIdGrupo($padre);
			$idHijo = $this->__getIdGrupo($hijo);
			$consulta = "select count(*) total from jerarquia where padre=? and hijo=?";
			$row = $this->basedatos->ExecuteQuery($consulta, array($idPadre,$idHijo));
			if($row[0]->total > 0){
				$this->error = 1;
				$mensaje = $this->mensaje->getMensaje('ADM_USR_045', array("grupo1"=>$idPadre,"grupo2"=>$idHijo));
				throw new Exception($mensaje, "045");
			}
			$consulta = "insert into jerarquia (padre,hijo) values (?,?)";
			$sth 	  = $this->basedatos->ExecuteNonQuery($consulta, array($idPadre,$idHijo));
			if(!$sth){
				$this->error = 1;
				$mensaje = $this->mensaje->getMensaje('ADM_USR_004', array());
				throw new Exception($mensaje, "004");
			}
		}
		
		/**
		 *	dado un login y una funcion, devuelve sobre que usuarios puede ejecutarla
		 *	Entrada:
		 *	 - login del usuario
		 *	 - nombre de la funcion
		 *	Salida:
		 *	 - usuarios => hash que tiene como llave el login de los usuarios
		 **/
		public function getUsuariosFuncion($login = "", $fun = ""){
			try{
				$idUsuario 	= $this->__getIdUsuario($login);
				$funcion 	= $this->__getFuncion($fun);
					
				$salida = array();
		
				if($funcion->valida_usuario == 'S'){
					$consulta = ' SELECT login FROM usuario ';
					$res = $this->basedatos->ExecuteQuery($consulta, array());
					foreach($res as $k => $v){
						$salida[$v->login] = 1;
					}
					return	$salida;
				}
				else{
					$marcados = array();
					$consulta = '	SELECT u.grupo hijo					'.
								'	FROM usr_grupo u,funcionalidad f	'.
								'	WHERE u.grupo = f.grupo				'.
								'		  AND usuario = ?				'.
								'		  AND funcion = ?				';
					$res = $this->basedatos->ExecuteQuery($consulta, array($idUsuario, $funcion->id));
						
					$cons_grupos =  '	SELECT hijo						'.
									'	FROM jerarquia					'.
									'	WHERE padre in(-1				';
						
					$cons_usrs	 =  '	SELECT login					'.
									'	FROM usuario u, usr_grupo ug	'.
									'	WHERE u.id = ug.usuario			'.
									'		  AND ug.grupo in(-1		';
					$seguir 		= 1;
					$primera_vez	= 1;
					while($seguir){
						$seguir		= 0;
						$in			= "";
						$valores 	= array();
		
						foreach($res as $k => $v){
							if(!isset($marcados[$v->hijo])){
								$in 				.= ",?";
								$valores[] 			= $v->hijo;
								$marcados[$v->hijo]	= 1;
								$seguir				= 1;
							}
						}
						if(!$primera_vez){
							$res = $this->basedatos->ExecuteQuery($cons_usrs . $in . ")", $valores);
							foreach($res as $k1 => $v1){
								$salida[$v1->login] = 1;
							}
						}
						$primera_vez = 0;
						if($seguir){
							$res = $this->basedatos->ExecuteQuery($cons_grupos . $in . ")", $valores);
						}
					}
					return $salida;
				}
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		/**
		 * dado una funcion, devuelve los grupos que la contienen
		 * Entrada:
		 * - funcion
		 * Salida
		 * - grupos => hash que tiene como llave el nombre de los grupos
		 **/
		public function getGruposFun($fun = ""){
			try{
				#obtengo el id del grupo
				$funcion	=	$this->__getFuncion($fun);
				$idFuncion  =   $funcion->id;
		
				$consulta	= 	' SELECT grupo.* 										'.
								'	FROM funcionalidad, funcion, grupo 					'.
								'	WHERE 	funcionalidad.grupo = grupo.id				'.
								'			AND funcionalidad.funcion = funcion.id		'.
								'			AND funcion.id = ?							';
				$res 		= $this->basedatos->ExecuteQuery($consulta, array($idFuncion));
					
				$grupos 	= array();
				foreach($res as $k => $v){
					$grupos[$v->nombre]	=	$v;
				}
				return $grupos;
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}

		/**
		 * Crea un grupo
		 * Entrada:
		 *	- nombre del grupo
		 *	- descripcion
		 *	- (opcional) lista de nombres de funciones a asociar al grupo
		 **/
		public function crearGrupo($nombre = "", $desc = "", $funciones  = array()){
			try{
				#agrego el grupo
				if (!isset($nombre) or !isset($desc) or ($nombre == "") or ($desc == "")){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_020', array());
					throw new Exception($mensaje, '020');
				}
		
				$consulta	=	' SELECT id FROM grupo where nombre = ? ';
				$res = $this->basedatos->ExecuteQuery($consulta, array($nombre));
				if(isset($res[0]->id) and ($res[0]->id != "")){
					$this->error = 1;
					$mensaje =$this->mensaje->getMensaje('ADM_USR_021', array("grupo" => $nombre));
					throw new Exception($mensaje, '021');
				}
		
				$consulta 	= ' INSERT INTO grupo (nombre, descripcion) VALUES (?,?) ';
				$res = $this->basedatos->ExecuteNonQuery($consulta, array($nombre, $desc));
		
				// commiteo para poder agregarle las funcionalidades al grupo
				//$this->finalizar();
		
				#agrego las funcionalidades
				if(count($funciones) > 0){
					foreach($funciones as $k => $func){
						$res = $this->agregarFuncionalidad($nombre,$func);
						/*
						hay que rollbackear
						if ($$res{error}==1){
						$self->eliminarGrupo($nombre);
						return $res;
						}
						*/
					}
				}
		
				$res = $this->agregarJerarquia("root",$nombre);
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
			
		/**
		 * asocia una funcion a un grupo
		 * Entrada:
		 *	- nombre del grupo
		 *	- nombre de la funcion
		 **/
		private function agregarFuncionalidad($grupo = "", $funcion = ""){
		  	try{
				#verifico que exista la funcion
				$funcionObtenida = $this->__getFuncion($funcion);
				$idFuncion = $funcionObtenida->id;
				
				#verifico que exista el grupo
				$idGrupo = $this->__getIdGrupo($grupo);
				
				$consulta 	= 	' select count(*) total		'.
								' from funcionalidad		'.
								' where grupo = ?			'.
				  				'		and funcion = ?		';
				$res 		= $this->basedatos->ExecuteQuery($consulta, array($idGrupo, $idFuncion));
	
				if($res[0]->total != 0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_020', array("funcion" => $funcion,"grupo" => $grupo));
					throw new Exception($mensaje, '020');
				}
	
				$consulta 	= ' INSERT INTO funcionalidad (grupo,funcion) VALUES (?,?) ';
				$res 		= $this->basedatos->ExecuteNonQuery($consulta, array($idGrupo, $idFuncion));
	
			}
			catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		# Valida si se pueden eliminar un conjunto de grupos
		# segun las reglas de la jerarquia
		# Entrada:
		#	-array de grupos a borrar
		# Salida:
		#	- si es valida la operacion, valido=1
		#	- sino valido=0, y en "msg" el porque no es valido.
		public function validarEliminarGrupos($grupos_a_borrar){
			try{
				if (!isset($grupos_a_borrar)){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_019', array());
					throw new Exception($mensaje, '019');
				}
				$ids_grupos_a_borrar = array();
				$in = array();
				foreach ($grupos_a_borrar as $grupo) {
					$idGrupo = $this->__getIdGrupo($grupo);
					$ids_grupos_a_borrar[] = $idGrupo;
					$in[] = '?';
				}
				# para cada grupo a borrar, obtengo sus hijos
				$hijos_grupos_a_borrar = array();
				$consulta_hijos = "select distinct hijo from jerarquia where padre = ? and hijo not in(";
				$consulta_hijos =  $consulta_hijos.join(",",$in).")";
				foreach ($ids_grupos_a_borrar as $grupo_a_borrar) {
					$aux = $ids_grupos_a_borrar;
					array_unshift($aux,$grupo_a_borrar);
					$res = $this->basedatos->ExecuteQuery($consulta_hijos, $aux);
					$hijos = array();
					foreach ($res as $row) {
						$hijos[] = $row->hijo;
					}
					$hijos_grupos_a_borrar[$grupo_a_borrar] = $hijos;
				}
				$padres_validados = array();
				foreach ($ids_grupos_a_borrar as $grupo_a_borrar) {
					# itero solo en el caso de que tenga hijos
					if(count($hijos_grupos_a_borrar[$grupo_a_borrar]) > 0){
						#obtengo los padres del grupo
						$consulta_padres = "select distinct padre from jerarquia where hijo = ? and padre not in (";
						$consulta_padres = $consulta_padres.join(",",$in).")";
						$aux = $ids_grupos_a_borrar;
						array_unshift($aux,$grupo_a_borrar);
						$sth = $this->basedatos->ExecuteQuery($consulta_padres, $aux);
						# empiezo a iterar entre los padres
						foreach ($sth as $row){
							$padre = $row->padre;
							# me fijo que no lo haya validado antes
							if(!isset($padres_validados[$padre])){
								# ahora me tengo que fijar cuales de los hijos de este
								# grupo estan entre los que voy a borrar
								$consulta_cuales = "select distinct hijo from jerarquia where padre = ? and hijo in(";
								$consulta_cuales = $consulta_cuales.join(",",$in).")";
								$aux = $ids_grupos_a_borrar;
								array_unshift($aux,$padre);
								$sth_cuales = $this->basedatos->ExecuteQuery($consulta_cuales, $aux);
								$subconjunto_nietos = array();
								# armo un hash con los hijos
								# a los que tengo que validar que el grupo
								# siga accediendo, que son los hijos
								# de sus hijos borrados
								foreach ($sth_cuales as $row){
									$h = $row->hijo;
									foreach ($hijos_grupos_a_borrar[$h] as $nieto){
										$subconjunto_nietos[$nieto] = 1;
									}
								}
								$nietos = array();
								foreach ($subconjunto_nietos as $n => $v){
									$nietos[] = $n;
								}
								if(count($nietos)>0){
									$marcados = array();
									$recorrida = array();
									$recorrida[] = $padre;
									$consulta_recorrida = "select distinct hijo from jerarquia where padre = ? and hijo not in(";
									$consulta_recorrida = $consulta_recorrida.join(",",$in).")";
									# recorro a partir del padre, hacia abajo
									while ((count($nietos)> 0) and (count($recorrida) > 0)){
										$actual = array_shift($recorrida);
										if(!isset($marcados[$actual])){
											$marcados[$actual] = 1;
											$aux = $ids_grupos_a_borrar;
											array_unshift($aux,$actual);
											$sth_recorrida = $this->basedatos->ExecuteQuery($consulta_recorrida, $aux);
											foreach ($sth_recorrida as $row){
												$recorrida[] = $row->hijo;
												if(isset($subconjunto_nietos[$row->hijo])){
													unset($subconjunto_nietos[$row->hijo]); // Esto elimina el elemento del array
													$nietos = array();
													foreach ($subconjunto_nietos as $n => $v){
														$nietos[] = $n;
													}
												}
											}
										}
									}
									if(count($nietos)>0){
										$consulta = "select nombre from grupo where id=?";
										$sth = $this->basedatos->ExecuteQuery($consulta, array($padre));
										$row = $sth[0];	
										$padre = $row->nombre;
										$nombres_nietos = array();
										foreach ($nietos as $h){
											$sth = $this->basedatos->ExecuteQuery($consulta, array($h));
											$row = $sth[0];
											$nombres_nietos[] = $row->nombre;
										}
										return array("valido"=>0,"msg"=>"El grupo ".$padre." queda desconectado de el o los grupos: ".join(",",$nombres_nietos));
									}
								} # if (tiene nietos)
							} # if (no fue validado)
						} # iteracion por padres
					} # if (el grupo a borrar tiene hijos)
				} # por cada grupo a borrar
				return array("valido"=>1);
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		# Valida si los grupo pasados como parametro son o descendientes o grupos del usuario pasado como parametro.
		# Entrada: 
		#	- nombre del usuario
		#	- nombre del grupo
		# Salida:
		#	- si es valida la operacion, valido =1
		#	- sino valido = 0, y en mensaje el porque no es valido
		public function validarDescendencia($login,$grupos){
			try{ 
				#array de grupos de descendientes 
				$res = $this->getArbolGruposUsr($login);// Devuelve todos los grupos al que pertenece el usuario, mas los grupos hijos en su jerarquia
				$grupos_validos = array();
				foreach($res as $clave => $valor){ // Armo un arreglo con los nombres de todos los grupos
					$grupos_validos[] = $valor["nombre"];
				}
				#array de grupos del usuario actual
				$res = $this->getGruposUsr($login); // Devuelve todos los grupos al que pertenece el usuario
				$grupos_usr = array(); 
				foreach($res as $clave => $valor){ // Armo un arreglo con los nombres de todos los grupos
					$grupos_usr[] = $clave;
				}
				$grupos_validos = array_merge($grupos_validos, $grupos_usr);
				#verifico si los grupos pasados como parametro son descendientes de los del usuario
				foreach ($grupos as $gru){
					$es_desc = 0;
					foreach ($grupos_validos as $gru_val){
						if (strcmp($gru_val, $gru) == 0) {
							$es_desc = 1;
							end($grupos_validos); 
						}
					}
					if ($es_desc ==0){
						return array("valido"=>0, "mensaje"=>"El grupo ".$gru." no es descendiente del usuario actual, no se puede ejecutar la operacion");
					}
				}
				return array("valido"=>1);
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		# Valida si un usuario puede asignar determinados padres a un grupo
		# segun las reglas de jerarquia
		# Entrada: 
		#	- nombre del usuario
		#	- nombre del grupo
		#	- array de padres asignados
		# Salida:
		#	- si es valida la operacion, valido = 1
		#	- sino valido=0, y en mensaje el porque no es valido
		public function validarJerarquia($login,$grupo,$padres_asig){
			try{
				//array de grupos validos como padres
				$res = $this->getArbolGruposUsr($login);// Devuelve todos los grupos al que pertenece el usuario, mas los grupos hijos en su jerarquia
				$grupos_validos = array();
				foreach($res as $clave => $valor){ // Armo un arreglo con los nombres de todos los grupos
					$grupos_validos[] = $valor["nombre"];
				}
				//array de grupos del usuario actual
				$res = $this->getGruposUsr($login); // Devuelve todos los grupos al que pertenece el usuario
				$grupos_usr = array(); 
				foreach($res as $clave => $valor){ // Armo un arreglo con los nombres de todos los grupos
					$grupos_usr[] = $clave;
				}
				$grupos_validos = array_merge($grupos_validos, $grupos_usr);
				//ahora verifico si puedo editarlo, 
				//desde mis grupos
				//obtengo todos los ascendentes hasta cubrir todos los grupos 
				//del usuario actual
				$visitados = array();
				#inicio desde los padres asignados
				$padres_act = $padres_asig;
				$cant_grupos_usr = count($grupos_usr)+1;
				$consulta = "select * from grupo, funcion, funcionalidad where funcionalidad.funcion = funcion.id and funcionalidad.grupo = grupo.id and grupo.nombre=? and funcion.nombre=?";	
				$visitados[$grupo] = 1;
				while (count($padres_act)>0){
					$act = array_shift($padres_act);
					if (!isset($visitados[$act])){
						//si es parte de los grupos del usuario, decremento contador
						foreach ($grupos_usr as $elem){
							if (strcmp($elem,$act) == 0){
								$cant_grupos_usr = $cant_grupos_usr - 1;
								//verifico si puedo editar desde este grupo
								//no puedo editar->continuo
								$sth = $this->basedatos->ExecuteQuery($consulta, array($act,"modificar grupo"));
								if(isset($sth[0])){
									$row = $sth[0];
									//si devuelve la consulta->hay un padre que puede editarlo
									if (isset($row[id])){
										return array("valido"=>1);
									}
								}								
								end($grupos_usr);
							}		
						}
						#lo marco como visitado			
						$visitados[$act] = 1;
						#si ya no hay grupos del usr a recorrer->salgo, no encontre lo buscado
						if ($cant_grupos_usr==0){
							return array("valido"=>0,"mensaje"=>"En estas condiciones ning&uacute;n grupo del usuario actual podr&iacute;a modificar el grupo en un futuro. No se puede ejecutar la operaci&oacute;n.");
						}
						#agrego al array los padres del padre que no fueron visitados aun
						#y que pertenecen a los descendientes del grupo del usr
						$res = $this->getPadresGrupo($act);
						$abuelos = array();
						foreach($res as $clave => $valor){ 
							$abuelos[] = $clave;
						}
						foreach($abuelos as $ab){ 
							#si no fue visitado
							if (!isset($visitados[$ab])){
								#y si es descendiente del usr actual
								foreach($grupos_validos as $valid){
									if (strcmp($valid,$ab) == 0){
										$padres_act[] = $ab;
									}
								} 
							}
						}
					}#endif
				}#endwhile
				return array("valido"=>0,"mensaje"=>"En estas condiciones ning&uacute;n grupo del usuario actual podr&iacute;a modificar el grupo en un futuro. No se puede ejecutar la operaci&oacute;n.");
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		#getPadresGrupo
		#Devuelve todos los grupos Padres del grupo dado
		#Entrada: 
		#	-nombre del grupo
		#Salida:
		#	- devuelve un hash cuyas claves
		# 	son los nombres de los grupos
		#	y cuyos valores son hashes con los datos de los mismos.
		public function getPadresGrupo($grupo){
			try{
				#obtengo el id del grupo
				$id = $this->__getIdGrupo($grupo);
				$consulta= "select grupo.* from grupo, jerarquia where jerarquia.hijo = ? and grupo.id = jerarquia.padre and grupo.nombre<>'root'";
				$sth = $this->basedatos->ExecuteQuery($consulta, array($id));
				$grupos = array();
				foreach($sth as $row){ 
					$grupos[$row->nombre] = $row;
				}
				return $grupos;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		#verifica que todas las funciones existentes se asignen al root
		#verifica que todos los grupos sean hijos directos del root
		public function mantenimientoRoot(){
			try{
				#verifico que todas las funciones pertenezcan al root
				$funciones = $this->getFunciones();
				foreach ($funciones as $nombre => $valor){
					try{
					$res = $this->agregarFuncionalidad("root",$nombre);
					}catch(Exception $e){
						if ($e->getCode() != 20){
							// el error que da cuando la funcion ya existe no me interesa
							$this->error = 1;
							throw new Exception( $e->getMessage( ) , (int)$e2->getCode( ) );
						}else{
							$this->error = 0;
						}
					}
				}
				$grupos = $this->getGrupos();
				foreach ($grupos as $nombre => $valor){
					try{
						$res = $this->agregarJerarquia("root",$nombre);
						// si ya existe tira la EXCEPCION de codigo 045
					}catch(Exception $e){
						if ($e->getCode() != 45){
							// el error que da cuando la funcion ya existe no me interesa
							$this->error = 1;
							throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
						}else{
							$this->error = 0;
						}
					}
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		#getFunciones
		#Devuelve todas las funciones definidas
		#Salida:
		#	- devuelve un hash cuyas claves
		# 	son los nombres de las funciones definidas
		#	y cuyos valores son hashes con los datos de las mismas.
		public function getFunciones(){
			try{
				$consulta = "select * from funcion";
				$sth = $this->basedatos->ExecuteQuery($consulta,array());
				$funciones = array();
				foreach($sth as $row){
					$funciones[$row->nombre] = $row;
				}
				return $funciones;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		#getGrupos
		#Devuelve todos los grupos existentes
		#Salida:
		#	- devuelve en clave "grupos" un hash cuyas claves
		# 	son los nombres de los grupos del sistema
		#	y cuyos valores son hashes con los datos de los mismos.
		public function getGrupos(){
			try{
				$consulta = "select * from grupo";
				$sth = $this->basedatos->ExecuteQuery($consulta,array());
				$grupos = array();
				foreach($sth as $row){
					$grupos[$row->nombre] = $row;
				}
				return $grupos; 
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		# crea el usuario root, el grupo root y le asigna el grupo al usuario
		# al grupo le asigno todas las funciones del sistema
		# Entrada:
		# 	-password del root
		public function crearRoot($pwd){
			try{
				// CREO EL GRUPO
				try{
					$idGrupoRoot = $this->__getIdGrupo("root"); // Devuelve el id de un grupo
					// Si no existe tira la EXCEPCION de codigo 017
				}catch(Exception $e){
					if ($e->getCode() != 17 ){
						// el error que da cuando la el grupo no existe no me interesa
						$this->error = 1;
						throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
					}else{
						$this->error = 0;
					}
				}
				try{
					$hashFunciones = $this->getFunciones(); // Retorna hash[nombreFuncion] = datosFuncion
				}catch(Exception $e){
					$this->error = 1;
					throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
				}
				if(isset($idGrupoRoot)){
					// Ya existe, no tengo que crearlo, pero por las dudas le asigno las funciones del sistema
					foreach ($hashFunciones as $nombreFuncion => $datos){
						try{
							$res = $this->agregarFuncionalidad("root",$nombreFuncion); // Asocia una funcion a un grupo
						}catch(Exception $e){
							if ($e->getCode() != 20){
								// el error que da cuando la funcion ya existe no me interesa
								$this->error = 1;
								throw new Exception( $e->getMessage( ) , (int)$e2->getCode( ) );
							}else{
								$this->error = 0;
							}
						}
					}
				}else{
					// Si no existe el grupo hay que crearlo
					$funciones = array();
					foreach ($hashFunciones as $nombreFuncion => $datos){
						$funciones[] = $nombreFuncion;
					}
					try{
						$res = $this->crearGrupo("root","root",$funciones); // Crea un grupo, si ya existe tira Excepsion codigo 021
					}catch(Exception $e){
						if ($e->getCode() != 21){
							// Si la excepcion no es que ya Existe el grupo
							$this->error = 1;
							throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
						}else{
							$this->error = 0;
						}
					}
				}
				// Le asigno al grupo su jerarquia
				try{
					$hashGrupos = $this->getGrupos(); // Retorna hash[nombreGrupo] = datosGrupo
				}catch(Exception $e){
					$this->error = 1;
					throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
				}
				foreach ($hashGrupos as $nombreGrupo => $datos){
						try{
							$res = $this->agregarJerarquia("root",$nombreGrupo); // Agrega la jerarquia
							// si ya existe tira la EXCEPCION de codigo 045
						}catch(Exception $e){
							if ($e->getCode() != 45){
								// el error que da cuando la funcion ya existe no me interesa
								$this->error = 1;
								throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
							}else{
								$this->error = 0;
							}
						}
				}
				// CREO EL USUARIO
				// Aca tengo que capturar la EXCEPCION y si es la de no existe el usuario crearlo
				try{
					$res = $this->__getIdUsuario("root"); // Devuelve el id de un usuario
				}catch(Exception $e){
					if ($e->getCode() == 15){
						// No Existe el usuario, hay que crearlo
						$this->error = 0;
						$idNew = $this->__crearUsuario("root",$pwd);
					}else{
						$this->error = 1;
						throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
					}
				}
				// ASIGNO EL USUARIO AL GRUPO 
				try{
					$res = $this->__asignarGrupo("root","root"); // Asigna un usuario a un grupo
				}catch(Exception $e){
					if($e->getCode() != 18){
						$this->error = 1;
						throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
					}else{
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_054', array());
						throw new Exception($mensaje, '054'); 
					}
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		#Cambia los atributos especificados del usuario, estos pueden ser
		# activado(S/N), habilitado(S/N),
		# externo(S/N) y/o resetear(S/N).
		#Entrada: 
		#	-nombre del usuario a modificar
		#	-atributos a modificar: hash que contiene 
		#			pares atributo,valor del atributo.
		public function modifUsuario($usuario,$atrib){
			try{
				if ((!isset($atrib["activado"])) and (!isset($atrib["habilitado"]))
				and (!isset($atrib["externo"])) and (!isset($atrib["resetear"]))){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_025', array());
					throw new Exception($mensaje, '025');
				}
				#verifico que exista el usuario
				$res_id = $this->__getIdUsuario($usuario);
				$id_usuario = $res_id["id"];
				#string a agregar a la consulta
				$cont_consulta = "";
				#array de valores para la ejecucion de la consulta
				$array_valores = array();
				#campos con formato "S" o "N"
				$camposSN = array("activado","habilitado","externo","resetear");
				#para cada uno si, existe en el hash, verifico formato y lo agrego a la consulta
				foreach($camposSN as $elem){
					$seteado = -1;
					if (isset($atrib[$elem])){
						#verifico formato, si no es valido retorno error
						if (strcmp($atrib[$elem],'S') == 0){
							$seteado=1;
						}else{
							if (strcmp($atrib[$elem],'N') == 0){
								$seteado=0;
							}else {
								$this->error = 1;
								$mensaje = $this->mensaje->getMensaje('ADM_USR_026', array("parametro"=>$elem));
								throw new Exception($mensaje,'026');
							}
						}
						
						#agrego campo y valor a la consulta
						if (strcmp($cont_consulta,"") != 0){
							$cont_consulta .= ",";
						}	
						$cont_consulta .= "$elem =? ";
						$array_valores[] = $seteado;
					}
				}
				
				//$cont_consulta =~ s/,$//;
				$array_valores[] = $id_usuario;
				$consulta = "update usuario set $cont_consulta where id = ?";
				print("$consulta");
				$sth = $this->basedatos->ExecuteNonQuery($consulta,$array_valores);
				if (!$sth){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_002', array());
					throw new Exception($mensaje, '002');
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		
		#Retorna los usuarios de los grupos pasados como parametro que tienen un perfil definido
		# activado(S/N), habilitado(S/N),
		# externo(S/N) y/o resetear(S/N).
		#Entrada: 
		#	- Arreglo de grupos de los cuales obtener los usuarios
		#Salida:
		#	- Arreglo que tiene como clave el login de los usurios y como contenido los datos 
		#	  de los usuarios.
		public function getUsuariosConPerfil($grupos){
			try{
				$where = "and (";
				$consulta = "";
				$array_valores = array();
				#si paso grupos verifico que existan
				if( count($grupos) > 0 ){
					#guardo grupos validos en el where
					foreach($grupos as $grupo){
						$id = $this->__getIdGrupo($grupo);
						$where .= "(ug.grupo=?) or ";	
						$array_valores[] = $id;
					}
					$where = preg_replace('/\sor\s$/',"", $where);
					$where .= ")";
					$consulta = "select distinct u.id, u.login, u.activado, u.resetear, u.habilitado, u.externo, p.* from usuario u join usr_grupo ug on u.id=ug.usuario left join perfil p on u.id=p.id where (ug.usuario = u.id) ".$where;
				}else{
					$consulta = "select distinct u.id,u.login,u.activado,u.resetear,u.habilitado,p.* from usuario u left join perfil p on u.id=p.id ";
				}
				$sth = $this->basedatos->ExecuteQuery($consulta,$array_valores);
				$usuarios = array();
				foreach($sth as $usuario){
					$login = $usuario->login;
					$usuarios[$login] = $usuario;
				}	
				return $usuarios;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		
		#getUsuarios
		#Si no especifico grupos, devuelve todos los usuarios del sistema
		#Si no, devuelve la union de los usuarios de los grupos especificados
		#Entrada: 
		#	-lista de grupos (puede ser vacia)
		#Salida:
		#	- devuelve un hash cuyas claves
		# 	son los login de los usuario obtenidos 
		#	y cuyos valores son hashes con los datos de los mismos. 
		public function getUsuarios($grupos){
			try{
				$where = "and (";
				$consulta = "";
				$array_valores = array();
				#si paso grupos verifico que existan
				if ( count($grupos) > 0 ){
					#guardo grupos validos en el where
					foreach( $grupos as $grupo ){
						$id = $this->__getIdGrupo($grupo);
						$where .= "(usr_grupo.grupo=?) or ";	
						$array_valores[] = $id;
					}
					$where = preg_replace('/\sor\s$/',"", $where);
					$where .= ")";
					$consulta = "select distinct usuario.id, usuario.login, usuario.activado, usuario.resetear, usuario.habilitado from usuario, usr_grupo where (usr_grupo.usuario = usuario.id) ".$where;
				}else{
					$consulta = "select distinct usuario.id, usuario.login, usuario.activado, usuario.resetear, usuario.habilitado from usuario";
				}
				$sth = $this->basedatos->ExecuteQuery($consulta,$array_valores);
				$usuarios = array();
				foreach($sth as $rows){
					$usuario = array();
					$usuario["id"] = $rows->id;		
					$usuario["login"] = $rows->login;
					$usuario["activado"] = $rows->activado;
					$usuario["resetear"] = $rows->resetear;		
					$usuario["habilitado"] = $rows->habilitado;
					$login = $usuario["login"];	
					$usuarios[$login] = $usuario;
					
				}
				return $usuarios;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		#getHijosGrupo
		#Devuelve todos los grupos hijo del grupo dado
		#Entrada: 
		#	-nombre del grupo
		#Salida:
		#	- devuelve un hash cuyas claves
		# 	son los nombres de los grupos
		#	y cuyos valores son hashes con los datos de los mismos.
		public function getHijosGrupo($grupo){
			try{
				#obtengo el id del grupo
				$id = $this->__getIdGrupo($grupo);
				$consulta = "select grupo.* from grupo, jerarquia where jerarquia.padre = ? and grupo.id = jerarquia.hijo";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($id));
				$grupos = array();
				foreach( $sth as $row ){
					$nombre = $row->nombre;
					$grupos[$nombre] = $row; 
				}
				return $grupos;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		
		#getGruposDescendientesUsr
		#Devuelve todos los grupos hijos en su jerarquia
		#Entrada: 
		#	-nombre del usuario
		#Salida:
		#	- devuelve un arreglo que en cada entrada contiene el nombre y la descripcion
		# 	  de uno de los grupos obtenidos 
		public function getGruposDescendientesUsr($login){
			try{
				#obtengo el id del usuario
				$idUsr = $this->__getIdUsuario($login);
				$salida = array();
				$marcados = array();
				$consulta = "select u.grupo hijo,g.nombre,g.descripcion from usr_grupo u,grupo g where g.id=u.grupo and usuario=?";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($idUsr));
				$cons_grupos = "select j.hijo,g.nombre, g.descripcion from jerarquia j,grupo g where g.id=j.hijo and padre in(-1";
				$seguir = 1;
				$primera = 1;
				while($seguir){
					$seguir = 0;
					$in = "";
					$valores = array();
					foreach( $sth as $g ){
						$hijo = $g->hijo;
						if(!isset($marcados[$hijo])){
							$in .= ",?";
							$valores[] = $hijo;
							if(!$primera){
								$marcados[$hijo] = 1;
								$nombre = $g->nombre;
								$descripcion = $g->descripcion;
								$salida[] = array("nombre"=>$nombre,"descripcion"=>$descripcion);
							}
							$seguir = 1;
						}
					}
					if($seguir){
						$primera = 0;
						$cons_grupos_aux = $cons_grupos.$in.")";
						$sth = $this->basedatos->ExecuteQuery($cons_grupos_aux,$valores);
					}
				}
				return	$salida;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		#3.2.4 Obtener Grupo
		# devuelve en un hash los datos de un grupo
		# Entrada: 
		#	- nombre del grupo
		# Salida
		# 	- hash con los campos
		public function getGrupo($nombre){
			try{
				$id = $this->__getIdGrupo($nombre);
				$consulta = "select * from grupo where id=?";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($id));
				if(count($sth) == 1){
					$row = $sth[0];
					return $row;
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
			
		#getFuncionesUsr
		#Devuelve todas las funciones a las que el usuario tiene acceso
		#Entrada: 
		#	-nombre del usuario
		#Salida:
		#	- devuelve un hash cuyas claves
		# 	son los nombres de las funciones obtenidas 
		#	y cuyos valores son hashes con los datos de las mismas.
		public function getFuncionesUsr($login){
			try{
				#obtengo el id del usuario
				$idUsr = $this->__getIdUsuario($login);
				$consulta = "select distinct ff.* from usr_grupo ug, funcionalidad f, funcion ff where ug.usuario=? and ug.grupo=f.grupo and f.funcion=ff.id";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($idUsr));
				$funciones = array();
				foreach($sth as $row){
					$funciones[$row->nombre] = $row;
				}
				return $funciones;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
				
		#eliminarUsrGrupo
		#Elimina un usuario dado de un grupo.
		#Entrada:
		#	- nombre del usuario
		#	- nombre del grupo
		public function eliminarUsrGrupo($login,$grupo){
			try{
				if( (strcmp($login,"root") == 0) and (strcmp($grupo,"root") == 0) ){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_056', array());
					throw new Exception($mensaje, '056');
				}
				$res = $this->perteneceGrupo($login,$grupo);
				if( !$res ){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_035', array("usuario"=>$login,"grupo"=>$grupo));
					throw new Exception($mensaje, '035');
				}
				$idUsr = $this->__getIdUsuario($login);
				$idGrupo = $this->__getIdGrupo($grupo);
				$consulta = "delete from usr_grupo where grupo=? and usuario=?";
				$sth = $this->basedatos->ExecuteNonQuery($consulta, array($idGrupo,$idUsr));
				if($sth){
					return TRUE;
				}else{
					return FALSE;
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		#perteneceGrupo
		#Determina si el usuario especificado pertenece al grupo especificado.
		#Entrada:
		#	- nombre del usuario
		#	- nombre del grupo
		#Salida:
		#	- en clave "pertenece" devuelve TRUE si pertenece o FALSE si no.
		public function perteneceGrupo($login,$grupo){
			try{
				#obtengo el id del usuario
				$idUsr = $this->__getIdUsuario($login);
				#obtengo el id del grupo
				$idGr = $this->__getIdGrupo($grupo);
				$consulta = "select count(*) total from usr_grupo where grupo=? and usuario=?";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($idGr,$idUsr));
				$rows = $sth[0];	
				if (($rows->total)>0){
					return TRUE;
				}
				return FALSE;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}


		#eliminarFuncion
		#Elimina una funcion
		#Entrada:
		#	-nombre de la funcion
		public function eliminarFuncion($funcion){
			try{
				#obtengo la funcion
				$idFunc = $this->__getIdFuncion($funcion);
				$idRoot = $this->__getIdGrupo("root");
				$consulta = "select count(*) total from funcionalidad where funcion=? and grupo<>?";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($idFunc,$idRoot));
				$rows = $sth[0];
				if ( $rows->total > 0 ){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_030', array());
					throw new Exception($mensaje, '030');	
				}
				$consulta = "delete from funcionalidad where funcion=?";
				$sth = $this->basedatos->ExecuteNonQuery($consulta, array($idFunc));
				if($sth){
					$consulta = "delete from funcion where id=?";
					$sth = $this->basedatos->ExecuteNonQuery($consulta, array($idFunc));
					if(!$sth){
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_004', array());
						throw new Exception($mensaje, '004');
					}
				}else{
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_004', array());
					throw new Exception($mensaje, '004');
				}			
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		# devuelve el id de una funcion  
		# Entrada: 
		#	- nombre de la funcion
		# Salida
		# 	- id de la funcion
		private function __getIdFuncion($funcion){
			try{
				if (!isset($funcion)){
					$funcion = "";
				}else{
					$funcion = preg_replace('/^\s*/',"", $funcion);
					$funcion = preg_replace('/\s*$/',"", $funcion);
				}
				if (strcmp($funcion,"") == 0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_000', array());
					throw new Exception($mensaje, '000');;
				}
				$consulta = "select id from funcion where nombre=?";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($funcion));
				if(count($sth)>0){
					$row = $sth[0];
				}else{
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_016', array("funcion"=>$funcion));
					throw new Exception($mensaje, '016');
				}
				return $row->id;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		#modifFuncion
		#Cambia los atributos especificados de la funcion,
		#estos pueden ser nombre y descripcion
		#Entrada: 
		#	-nombre de la funcion
		#	-atributos a modificar: arreglo que contiene 
		#			pares atributo,valor del atributo.
		public function modifFuncion($funcion,$valores){
			try{
				#obtengo la funcion
				$idFunc = $this->__getIdFuncion($funcion);
				$consulta = "update funcion set ";
				$valores_a_mod = array();
				$setea_algo=0;
				if (isset($valores["nombre"])){
					$setea_algo = 1;
					try{
						$res = $this->__getIdFuncion($valores["nombre"]);
						if(strcmp($valores["nombre"],$funcion) != 0){
							$this->error = 1;
							$mensaje = $this->mensaje->getMensaje('ADM_USR_031',array());
							throw new Exception($mensaje, '031');
						}
					}catch(Exception $e){
						if($e->getCode() != 16){
							$this->error = 1;
							throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
						}else{
							$this->error = 0;
						}
					}
					$consulta.= "nombre=?";
					$valores_a_mod[] = $valores["nombre"];
				}
				if (isset($valores["descripcion"])){
					if($setea_algo){
						$consulta.= ",";
					}
					$setea_algo = 1;
					$consulta.= "descripcion=?";
					$valores_a_mod[] = $valores["descripcion"];
				}
				if (!$setea_algo){
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_034', array("funcion"=>$funcion));
						throw new Exception($mensaje, '034');
				}
				$consulta.= " where id=?";
				$valores_a_mod[] = $idFunc;
				$sth = $this->basedatos->ExecuteNonQuery($consulta,$valores_a_mod);
				if( $sth==0 ){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_004', array("funcion"=>$funcion));
					throw new Exception($mensaje, '004');
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
			
		# Agregar Funcion
		# agrega una funcion
		# Entrada:  
		#	- nombre de la funcion
		#	- descripcion de la funcion
		#	- valida_usuario
		#	- valida_grupo
		public function agregarFuncion($funcion,$descripcion,$valida_usuario,$valida_grupo){
			try{
				if(!isset($valida_usuario)){
					$valida_usuario = 'N';
				}
				if(!isset($valida_grupo)){
					$valida_grupo = 'N';
				}
				if( ( !(strcmp($valida_usuario,'S') == 0 ) and !(strcmp($valida_usuario,'N') == 0 )) or
					( !(strcmp($valida_grupo,'S') == 0 ) and !(strcmp($valida_grupo,'N') == 0 )) ){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_051', array());
					throw new Exception($mensaje, '051');
				}
				if (isset($funcion)){
					$funcion = preg_replace('/^\s*/',"", $funcion);
					$funcion = preg_replace('/\s*$/',"", $funcion);
				}else{
					$funcion ="";
				}
				if (strcmp($funcion,"") == 0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_000', array());
					throw new Exception($mensaje, '000');
				}
				if (isset($descripcion)){
					$descripcion = preg_replace('/^\s*/',"", $descripcion);
					$descripcion = preg_replace('/\s*$/',"", $descripcion);
				}else{
					$descripcion ="";
				}	
				if (strcmp($descripcion,"") == 0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_041', array());
					throw new Exception($mensaje, '041');
				}
				$consulta = "select count(*) total from funcion where nombre=?";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($funcion));
				if(count($sth)>0){
					$row = $sth[0];
				}else{
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_016', array("funcion"=>$funcion));
					throw new Exception($mensaje, '016');
				}
				if ($row->total > 0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_031', array("funcion"=>$funcion));
					throw new Exception($mensaje, '031');
				}
				$consulta = "insert into funcion (nombre,descripcion,valida_usuario,valida_grupo) values (?,?,?,?)";
				$idNew 	  = $this->basedatos->ExecuteNonQuery($consulta,array($funcion,$descripcion,$valida_usuario,$valida_grupo), true);
				if($sth==0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_004', array("funcion"=>$funcion));
					throw new Exception($mensaje, '004');
				}
				$res = $this->agregarFuncionalidad("root",$funcion);
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		# Eliminar funcionalidad
		# elimina una asociacion grupo/funcion
		# Entrada: 
		#	- nombre de la funcion
		#	- nombre del grupo
		public function eliminarFuncionalidad($funcion,$grupo){
			try{
				$idFunc = $this->__getIdFuncion($funcion);
				$idGrupo = $this->__getIdGrupo($grupo);
				$consulta = "select count(*) total from funcionalidad where funcion=? and grupo=?";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($idFunc,$idGrupo));
				if(count($sth)>0){
					$row = $sth[0];
				}else{
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_016', array("funcion"=>$funcion));
					throw new Exception($mensaje, '016');
				}
				if ($row->total == 0){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_032', array("funcion"=>$funcion,"grupo"=>$grupo));
					throw new Exception($mensaje, '032');
				}
				$consulta = "delete from funcionalidad where grupo=? and funcion=?";
				$sth 	  = $this->basedatos->ExecuteNonQuery($consulta, array($idGrupo,$idFunc));
				if(!$sth){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_004', array());
					throw new Exception($mensaje, '004');
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		# Eliminar Grupo
		# elimina un grupo junto con sus asociaciones a funciones
		# Entrada: 
		#	- nombre del grupo
		public function eliminarGrupo($grupo){
			try{
				#obtengo el grupo
				$idGrupo = $this->__getIdGrupo($grupo);
				$consulta = "select count(*) total from usr_grupo where grupo=?";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($idGrupo));
				if(count($sth)>0){
					$row = $sth[0];
				}else{
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_016', array("funcion"=>$funcion));
					throw new Exception($mensaje, '016');
				}
				if ( $row->total >0 ){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_033', array("grupo"=>$grupo));
					throw new Exception($mensaje, '033');
				}
				#elimino posibles ocurrencias en la tabla jerarquia
				$consulta = "delete from jerarquia where padre=? or hijo=?";
				$sth 	  = $this->basedatos->ExecuteNonQuery($consulta, array($idGrupo,$idGrupo));
				#elimino posibles ocurrencias en la tabla funcionalidad
				$consulta = "delete from funcionalidad where grupo=?";
				$sth 	  = $this->basedatos->ExecuteNonQuery($consulta, array($idGrupo));
				$consulta = "delete from grupo where id=?";
				$sth 	  = $this->basedatos->ExecuteNonQuery($consulta, array($idGrupo));
				if(!$sth){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_004', array());
					throw new Exception($mensaje, '004');
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		# Modificar grupo
		# modifica los datos de un grupo
		# Entrada: 
		#	- nombre del grupo
		#	- referencia a hash que puede tener los valores:
		#			nombre => nuevo nombre del grupo
		#			descripcion => nueva descripcion del grupo
		public function modifGrupo($grupo,$atrib){
			try{
			print("El contenido de la variable atrib es: ");
			var_dump($atrib);
				if ( (!isset($atrib["nombre"])) and (!isset( $atrib["descripcion"])) ){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_020', array());
					throw new Exception($mensaje, '020');
				}
				$id = $this->__getIdGrupo($grupo);
				#verifico que no exista un grupo con el nombre que quiero poner
				if ( (isset($atrib["nombre"])) and (strcmp($atrib["nombre"],$grupo) != 0) ){
					try{
						$res_n = $this->__getIdGrupo($atrib["nombre"]); 
					}catch(Exception $e){
						if($e->getCode() != 17){
							$this->error = 1;
							throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
						}else{
							$this->error = 0;
						}
					}
					if (isset($res_n)){
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_021', array("grupo"=>$atrib["nombre"]));
						throw new Exception($mensaje, '021');
					}
				}
				$valores = "";
				$array_valores = array();
				if (isset($atrib["nombre"]) and ( strcmp($atrib["nombre"],"") != 0 )){
						$valores .= "nombre =? ";
						$array_valores[] = $atrib["nombre"];
				}
				if (isset($atrib["descripcion"]) and ( strcmp($atrib["descripcion"],"") != 0 )){
					if(strcmp($valores,"") != 0 ){
						$valores .= ",";
					}
					$valores .= "descripcion =? ";
					$array_valores[] = $atrib["descripcion"];
				}
				$valores = preg_replace('/,$/',"", $valores);
                $consulta = "update grupo set $valores where id = ?";
				$array_valores[] = $id;
				$sth = $this->basedatos->ExecuteNonQuery($consulta,$array_valores);
				if (!$sth){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_002', array());
					throw new Exception($mensaje, '002');
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		# Elimina el perfil de un usuario
		# Entrada: 
		#	- login del usuario
		public function eliminarPerfil($nombre){
			try{
				$id_usuario = $this->__getIdUsuario($nombre);
				var_dump($id_usuario);
				$consulta = "delete from perfil where id=?";
				$sth 	  = $this->basedatos->ExecuteNonQuery($consulta, array($id_usuario));
				if (!$sth){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_014', array());
					throw new Exception($mensaje, '014');
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		# Modificar Perfil
		# modifica el perfil de un un usuario
		# Entrada: 
		#	- login del usuario
		#	- hash con la forma columna=>valor
		public function modifPerfil($login,$hash){
			try{
				#obtengo el id del usuario
				$idUsr = $this->__getIdUsuario($login);
				#armo el update
				$seteos = "";
				$array_val = array();
				$ok = 0;
				foreach ($hash as $campo => $valor){
					$ok = 1;
					if( strcmp($seteos,"") != 0 ){
						$seteos .= ",";
					}
					$seteos .= $campo."=?";
					$array_val[] = $valor;
				}
				if ( $ok == 0 ){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_034', array());
					throw new Exception($mensaje, '034');
				}	
				if (strcmp($seteos,"") != 0){
					$array_val[] = $idUsr;
					$consulta = "update perfil set $seteos where id= ?";
					$sth = $this->basedatos->ExecuteNonQuery($consulta,$array_val);
					if (!$sth){#si no hizo update sobre ninguna fila=> no existia el perfil
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_014', array());
						throw new Exception($mensaje, '014');
					}
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		# genera un password en forma aleatoria
		# Entrada: 
		#	- largo del password
		# Salida
		# 	- password generada
		public function generarPwd($largo){
			try{
				$pasword = "";
				for($i=0; $i<$largo; $i++) {
					$opciones = array('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','2','3','4','5','6','7','8','9');
					$max = count($opciones)-1;
					$posicion = rand(0,$max);
					$carcacter = $opciones[$posicion];
					$pasword .= $carcacter;
				}
				
				if (strlen($pasword) != $largo){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_011', array());
					throw new Exception($mensaje,'011');
				}
				return $pasword;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		# Funcion sin probar que no se que se supone que hace
		public function getIdConsultaPerfil($columna,$valor,$consulta){
			try{
				$texto = $consulta;	
				if (preg_match("/select(.*)from/i", $texto,$matches)){ 
					$texto = $matches[1];
				}else{
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_084', array("CAMPO"=>$columna));
					throw new Exception($mensaje, '084');
				}
				$columnas_a_parsears = preg_split(",",$texto);
				$nombre_columna = "";
				foreach($columnas_a_parsears as $columna_a_parsear){
					$var = $columna_a_parsear;
					if (preg_match("m/^\s*\w+\.(\w+)\s+valor\s*$/i", $var,$matches)){ # tabla.columna valor
						$var = $matches[1];
					}
					elseif(preg_match("m/^\s*\w+\.(valor)\s*$/i", $var,$matches)){	# tabla.valor
						$var = $matches[1];
					}
					elseif(preg_match("m/^\s*(\w+)\s+valor\s*$/", $var,$matches)){	# columna alias
						$var = $matches[1];
					}
					elseif(preg_match("m/^\s*(valor)\s*$/", $var,$matches)){	# columna
						$var = $matches[1];
					}
					if(strcmp($var,"")!=0){
						$nombre_columna = $var ;
						$ultimo = end($columnas_a_parsears);
					}
				}
				$pertenece = 0;
				$id = "";
				if(strcmp($nombre_columna,"") == 0){
					$sth = $this->basedatos->ExecuteQuery($consulta,array());
					$cantidad = count($sth);
					$maximo = $cantidad - 1;
					$ind = 0;
					while(($pertenece == 0)and($ind <= $maximo)){
						$row = $sth[$ind];
						if( strcmp($row->valor,$valor) == 0 ){
							$pertenece = 1;
							$id = $row->id;
						}
					}
				}else{
					$consulta .= " and }.$nombre_columna.q{=?";
					$sth = $this->basedatos->ExecuteQuery($consulta,array($valor));
					if(count($sth)>0){
						$row = $sth[0];
						$id = $row->id;
						$pertenece = 1;
					}else{
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_004', array());
						throw new Exception($mensaje, '004');
					}
				}
				if( $pertenece == 0 ){
					$this->error = 1;
					$mensaje = $this->mensaje->getMensaje('ADM_USR_083', array("CAMPO"=>$columna));
					throw new Exception($mensaje,'083');
				}
				return $id;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		# Funcion sin probar que no se que se supone que hace
		public function getCamposPerfilGrupos($grupos){
			try{
				$camposperfil = array();
				if(count($grupos) == 0){
					return $camposperfil;
				}
				$consulta = "select c.* from campo c,campo_grupo cg,grupo g where c.id=cg.campo and g.id=cg.grupo and g.nombre in (''";
				foreach($grupos as $g){
					$consulta .= ",?";
				}
				$consulta .= ")";
				$sth = $this->basedatos->ExecuteQuery($consulta,array($grupos));
				foreach($sth as $row){
					$camposperfil[$row->id] = $row;
				}
				return $camposperfil;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}			
		}
		
		# Funcion sin probar que no se que se supone que hace
		public function getValoresValidosCampo($idCampo,$tiene_val_val,$consulta){
			try{
				$val_val = array();
				$consulta = preg_replace('/^\s*/',"", $consulta);
				$consulta = preg_replace('/\s*$/',"", $consulta);
				if( strcmp($tiene_val_val,"S") == 0 ){
					$select = "select id,valor from valor_valido where campo=?";
					$sth = $this->basedatos->ExecuteQuery($select,array($idCampo));
				}
				elseif( strcmp($consulta,"") != 0 ){
					$sth = $this->basedatos->ExecuteQuery($consulta,array());
				}
				else{
					return array("tiene_val_val"=>'N',"valores_validos"=>$val_val);
				}
				foreach($sth as $row){
					$val_val[$row->id] = $row->valor;
				}
				return array("tiene_val_val"=>'S',"valores_validos"=>$val_val);
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		# Funcion sin probar que no se que se supone que hace
		public function validarPerfilGrupos($perfil,$grupos){
			try{
				$camposperfil = $this->getCamposPerfilGrupos($grupos);
				foreach($camposperfil as $campoperfil){
					if(!isset($perfil[$campoperfil["columna"]])){
						$perfil[$campoperfil["columna"]] = "" ;
					}
					if( ( strcmp($perfil[$campoperfil["columna"]],"") == 0 ) and ( strcmp($campoperfil["acepta_nulo"],"N") == 0 ) ){
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_080', array("CAMPO"=>$campoperfil["columna"]));
						throw new Exception($mensaje,'080');
					}
					$campoperfil["formato"] = preg_replace('/\s*/',"", $campoperfil["formato"]);
					if( (strcmp($campoperfil["formato"],"") == 0) and (!preg_match($campoperfil["formato"],$perfil[$campoperfil["columna"]] ,$matches)) ){
						$this->error = 1;
						$mensaje = $this->mensaje->getMensaje('ADM_USR_081', array("CAMPO"=>$campoperfil["columna"]));
						throw new Exception($mensaje,'081');
					}
					if( strcmp($campoperfil["es_fecha"],"S") == 0 ){
						$error = 1;
						if(preg_match("/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/",$perfil[$campoperfil["columna"]] ,$matches)){
							$error=0;
							if(($matches[1]>31) or ($matches[1]<1)){ #dia valido
								$error = 1;
							}
							if(($matches[2]>12) or ($matches[2]<1)){ #mes valido
								$error = 1;
							}
							if(($matches[1]>29) or ($matches[2]==2)){ #febrero
								$error = 1;
							}
							if( (($matches[1]>28) and ($matches[2]==2)) or (($matches[3] % 4 == 0) and ($matches[3] % 100 != 0)) or ($matches[3] % 400 == 0) ){ #febrero bisciesto
								$error = 1;
							}
							if( ($matches[1]>30) and (($matches[2]==4) or ($matches[2]==6) or ($matches[2]==9) or ($matches[2]==11)) ){ 
								$error = 1;
							}
							if($error==0){
								$perfil[$campoperfil["columna"]] = $matches[3].$matches[2].$matches[1];
							}
						}
						if($error){
							$this->error = 1;
							$mensaje = $this->mensaje->getMensaje('ADM_USR_081', array("CAMPO"=>$campoperfil["columna"]));
							throw new Exception($mensaje,'081');
						}
					}
					if( strcmp($campoperfil["tiene_val_val"],"S") == 0 ){
						$consulta = "select count(*) cant from valor_valido where campo=? and valor=?";
						$sth = $this->basedatos->ExecuteQuery($consulta,array($campoperfil["id"],$perfil[$campoperfil["columna"]]));
						$row = $sth[0];
						if($row->cant == 0){
							$this->error = 1;
							$mensaje = $this->mensaje->getMensaje('ADM_USR_082', array("CAMPO"=>$campoperfil["columna"]));
							throw new Exception($mensaje,'082');
						}
					}
					$campoperfil["consulta"] = preg_replace('/\s*/',"", $campoperfil["consulta"]);
					if( strcmp($campoperfil["consulta"],"") != 0){
						$consulta = $campoperfil["consulta"];
						$id = $this->getIdConsultaPerfil($campoperfil["columna"],$perfil[$campoperfil["columna"]],$consulta);
						$perfil[$campoperfil["columna"]] = $id;
					}
				}
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		public function crearCampo($columna,$formato,$acepta_nulo,$descripcion,$explicacion_formato,$orden,$tiene_val_val,$consulta_campo,$es_fecha){
			try{
				$consulta = "insert into campo (columna,formato,acepta_nulo,descripcion,explicacion_formato,orden,tiene_val_val,consulta,es_fecha) values (?,?,?,?,?,?,?,?,?)";
				$idNew 	  = $this->basedatos->ExecuteNonQuery($consulta, array($columna,$formato,$acepta_nulo,$descripcion,$explicacion_formato,$orden,$tiene_val_val,$consulta_campo,$es_fecha), true);
				return $idNew;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}	
		}
		
		
		public function asociarCampoGrupo($idCampo,$grupo){
			try{
				$idGrupo = $this->__getIdGrupo($grupo);
				$consulta = "insert into campo_grupo (campo,grupo) values (?,?)";
				$idNew 	  = $this->basedatos->ExecuteNonQuery($consulta, array($idCampo,$idGrupo), true);
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}
		
		
		public function asociarValorValidoCampo($idCampo,$valor){
			try{
				$consulta = "insert into valor_valido (campo,valor) values (?,?)";
				$new_id = $this->basedatos->ExecuteNonQuery($consulta, array($idCampo,$valor), true);
				return $new_id;
			}catch(Exception $e){
				$this->error = 1;
				throw new Exception( $e->getMessage( ) , (int)$e->getCode( ) );
			}
		}		
		

		
		
				
	} // Fin de la clase
	
?>