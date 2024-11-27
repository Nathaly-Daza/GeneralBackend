<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Support\Facades\DB;
use Illuminate\Routing\Controller as BaseController;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    // Método para activar un trigger que registra una nueva inserción en la base de datos
    public static function NewRegisterTrigger($new_description,$new_typ_id,$use_id)
    {

         // Construir la sentencia SQL para llamar al procedimiento almacenado 'new_register'
        $trigger = "CALL new_register('" . addslashes($new_description) . "', $new_typ_id,6,$use_id)";

        // Ejecutar la sentencia SQL
        DB::statement($trigger);
    }

    // Método para validar si un valor ya existe en una tabla, excluyendo un registro específico
    public function validate_exists($data, $table, $column, $PK, $pk){

        // Obtener todos los valores de la columna especificada junto con su clave primaria
        $values = DB::table($table)->get([$PK, $column]);
        foreach ($values as $value) {
            // Si el valor coincide con los datos y la clave primaria no es igual al registro excluido, devuelve 0
            if ($value->$column == $data && $value->$PK != $pk) {
                return 0;
            }
        }

        // Si no se encuentra ninguna coincidencia, devuelve 1
        return 1;
    }

    public static function Unauthenticated()
    {
        return response()->json([
            'message'=> "Unauthenticated."
        ],401);
    }
}
