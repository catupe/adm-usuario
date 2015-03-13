<?php
    define('PHP_TAB', "\t");
	
    class Configuracion{
	
        private $ruta_archivo 	= null;
        private $ambiente       = null;
        private $datos          = null;
		private $datos_todos    = null;
        private $mensaje        = null;
		
        function Configuracion($archivo = "", $ambiente = ""){
            if($archivo == "" OR !file_exists($archivo)){
                throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
            }
            $this->ruta_archivo = $archivo;
            $this->ambiente     = $ambiente;

            $salida = array();
            $salida = parse_ini_file ($this->ruta_archivo, true);
            if(!$salida){
                throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
            }
			
			$this->datos_todos 	= $salida;
            $this->datos 		= $salida[$this->ambiente];
            return $this->datos;
        }
        function getRutaArchivo(){
            return $this->ruta_archivo;
        }
        function getDato($dato = ""){
			if(!isset($this->datos[$dato])){
				throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
			}
			return $this->datos[$dato];
        }
        /*
         * $arr_datos es un hash con el siguiente formato [dato => valor]
         */
        function setDato($ambiente = "desarrollo", $arr_datos){
            $fp = fopen($this->ruta_archivo, 'w');
            if(!$fp){
                throw new Exception("ERROR :: ". __CLASS__ . " :: " . __METHOD__ ." line ". __LINE__, 100);
            }
			foreach ($arr_datos as $k => $v){
            	$this->datos_todos[$ambiente][$k] = $v;
			}
			
			$str = "";
			foreach($this->datos_todos as $amb => $dat_n1){
				$str .= "[" . $amb . "]".PHP_EOL;
				foreach($dat_n1 as $k_n1 => $dat_n2){
					$str .= $k_n1 . " = " . $dat_n2 . PHP_EOL;
				}
				$str .= PHP_EOL;
			}
			fwrite($fp, $str);
			/*
            foreach ($arr_datos as $k => $v){
                fwrite($fp, "\n");
                fwrite($fp, $k." = ".$v);
            }
			*/
            fclose($fp);
        }
        static function getAmbiente($ruta_ambiente = ""){
            
            if($ruta_ambiente == "" OR !file_exists($ruta_ambiente)){
                throw new Exception($this->mensaje->getMensaje('012', array($ruta_ambiente)), 1);
            }
            $conf = parse_ini_file($ruta_ambiente);
            if(!$conf){
                throw new Exception($this->mensaje->getMensaje('013', array($ruta_ambiente)), 1);    
            }
            return $conf["ambiente"];            
        }
    }
?>