<?php

    class Mensajes{

        private static $instancia;
       
        private $mensajes = array
								("ADM_USR_000"=>"El nombre de la funcion no puede ser nulo.",
								 "ADM_USR_001"=>"El login del usuario no puede ser nulo.",
								 "ADM_USR_002"=>"Error al conectarse a la base de datos.",
								 "ADM_USR_003"=>"Login o password vacios.",
								 "ADM_USR_004"=>"Error al preparar la consulta.",
								 "ADM_USR_005"=>"Ya existe un usuario '#usuario#'.",
								 "ADM_USR_006"=>"Se intenta eliminar un usuario que no existe.",
								 "ADM_USR_007"=>"Error al eliminar de la tabla usr_grupo.",
								 "ADM_USR_008"=>"Error al eliminar de la tabla usuario.",
								 "ADM_USR_009"=>"Error al eliminar el perfil del usuario.",
								 "ADM_USR_010"=>"Error al actualizar password.",
								 "ADM_USR_011"=>"Error al generar la password.",
								 "ADM_USR_012"=>"",
								 "ADM_USR_013"=>"Ya existe un perfil para el usuario #usuario#",
								 "ADM_USR_014"=>"No existe un perfil para el usuario *usuario*",
								 "ADM_USR_015"=>"El usuario '#usuario#' no existe.",
								 "ADM_USR_016"=>"La funcion '#funcion#' no existe.",
								 "ADM_USR_017"=>"El grupo '#grupo#' no existe.",
								 "ADM_USR_018"=>"El usuario '#usuario#' ya esta asignado al grupo '#grupo#'.",
								 "ADM_USR_019"=>"El nombre del grupo no puede ser nulo.",
								 "ADM_USR_020"=>"El nombre del grupo y la descripcion no pueden ser nulos.",
								 "ADM_USR_021"=>"Ya existe un grupo con el nombre '#grupo#'.",
								 "ADM_USR_023"=>"Parametro 'activado' invalido.",
								 "ADM_USR_024"=>"Parametro 'habilitado' invalido.",
								 "ADM_USR_025"=>"Error en los parametros, no coinciden con las columnas.",
								 "ADM_USR_026"=>"Parametro '#parametro#' invalido.",
								 "ADM_USR_030"=>"La funcion esta asociada a un grupo.",
								 "ADM_USR_031"=>"Ya existe una funcion con el nombre '#funcion#'.",
								 "ADM_USR_032"=>"La funcion '*funcion*' no esta asignada al grupo '*grupo*'.",
								 "ADM_USR_033"=>"Hay usuarios asignados al grupo '#grupo#'.",
								 "ADM_USR_034"=>"No indico valores a cambiar.",
								 "ADM_USR_035"=>"El usuario '#usuario#' no pertenece al grupo '#grupo#'.",
								 "ADM_USR_040"=>"",
								 "ADM_USR_041"=>"La descripci�n no puede ser nula.",
								 "ADM_USR_044"=>"",
								 "ADM_USR_045"=>"La relacion jerarquica '*grupo1*'-'*grupo2*' ya existe.",
								 "ADM_USR_046"=>"La funcion '#funcion#' ya esta asignada al grupo '#grupo#'.",
								 "ADM_USR_047"=>"La relacion jerarquica no existe.",
								 "ADM_USR_048"=>"Usuario o password incorrecto.",
								 "ADM_USR_049"=>"Los parametros no pueden ser vacios.",
								 "ADM_USR_050"=>"Debe especificar un largo.",
								 "ADM_USR_051"=>"Los parametros valida_usuario y valida_grupo deben ser S o N",
								 "ADM_USR_052"=>"No pudo crearse el grupo root.",
								 "ADM_USR_053"=>"No pudo crearse el usuario root.",
								 "ADM_USR_054"=>"No pudo asignarse el grupo al usuario root.",
								 "ADM_USR_055"=>"No se pueden borrar las relaciones jerarquicas del root.",
								 "ADM_USR_056"=>"El usuario root debe pertenecer al grupo root.",
								 "ADM_USR_057"=>"El usuario root no puede ser eliminado.",
								 "ADM_USR_058"=>"Debe especificar por lo menos un grupo.",
								 "ADM_USR_059"=>"En estas condiciones ning&uacute;n grupo del usuario actual podr&iacute;a modificar el grupo en un futuro. No se puede ejecutar la operaci&oacute;n.",
								 "ADM_USR_080"=>"El campo #CAMPO# no puede ser nulo.",
								 "ADM_USR_081"=>"El formato del campo #CAMPO# no es v�lido.",
								 "ADM_USR_082"=>"El valor del campo #CAMPO# no es un valor v�lido para el mismo.",
								 "ADM_USR_083"=>"El valor del campo #CAMPO# no se encuentra en la consulta asociada al mismo.",
								 "ADM_USR_084"=>"La consulta asociada al campo #CAMPO# est� mal formada.",
								 "ADM_USR_085"=> "El ip no puede ser nulo",
								 "ADM_USR_086"=>"No existe el par ip grupo",
								 "ADM_USR_087"=>"La clave no tiene el formato adecuado.",
								 "ADM_USR_088"=>"Ya existe la ip para este grupo.",
								 "ADM_USR_089"=>"Parametro 'externo' invalido.",
								 );

        public function __construct(){}
        public static function getInstance(){
            if (  !self::$instancia instanceof self)
            {
             self::$instancia = new self;
            }
            return self::$instancia;
        }
        /*
         *    Recibe un codigo de mensaje y un array de parametros
         *    Sustituye cada elemento de parametros por el correspondiente de mensaje
         */
        public function getMensaje($codigoMensaje = "", $params = array()){
            $mensaje = $this->mensajes[$codigoMensaje];
            foreach($params as $k => $v){
                $mensaje = preg_replace("/#$k#/", $v, $mensaje);
            }
            return $mensaje;
        }
    }

?>