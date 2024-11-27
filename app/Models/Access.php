<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class Access extends Model
{
    use HasFactory;

    // Definición de las propiedades del modelo Access
    protected $primaryKey = 'acc_id'; // Clave primaria personalizada
    protected $table = 'access'; // Nombre de la tabla en la base de datos
    protected $fillable = [ // Campos que se pueden asignar de manera masiva
        'acc_status',
        'proj_id',
        'use_id'
    ];
    public $timestamps = false; // Desactivar los timestamps created_at y updated_at
    public static function select()
    {
        // Consulta SQL para seleccionar todos los registros de acceso con información relacionada
        $access = DB::select("SELECT access.acc_id, access.acc_status, projects.proj_name, access.use_id, users.use_mail,
            persons.per_id, persons.per_name, persons.per_document, projects.proj_id
            FROM access
            INNER JOIN projects ON access.proj_id = projects.proj_id
            INNER JOIN users ON access.use_id = users.use_id
            INNER JOIN persons ON users.use_id = persons.per_id");

        return $access; // Retornar los resultados de la consulta
    }
    public static function search($id){
                // Consulta SQL para buscar un registro de acceso por su ID con información relacionada

        $access = DB::select("SELECT access.acc_id,access.acc_status,projects.proj_name, access.use_id,users.use_mail,persons.per_id, persons.per_name,persons.per_document,projects.proj_id FROM access
        INNER JOIN projects ON access.proj_id = projects.proj_id
        INNER JOIN users ON access.use_id = users.use_id
        INNER JOIN persons ON users.use_id = persons.per_id WHERE $id = access.acc_id;");
        return $access[0]; // Retornar el primer resultado
    }
}
