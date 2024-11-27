<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class Project extends Model
{
    use HasFactory;
    //=========IMPORTANTE ADAPTAR AL MODELO=============
     // Nombre de la tabla asociada al modelo
     protected $table = 'projects';

     // Define la clave primaria personalizada
     protected $primaryKey = 'proj_id';

     // Define los atributos que se pueden asignar en masa
     protected $fillable = [
         'proj_name',
         'are_id',
     ];

     // Indica que el modelo no utiliza marcas de tiempo
     public $timestamps = false;

    //  * Método estático para seleccionar todos los proyectos con el nombre del área correspondiente.
    public static function select(){
        $projects = DB::select("SELECT projects.proj_id, projects.proj_name, areas.are_name,projects.are_id FROM projects
        INNER JOIN areas ON projects.are_id = areas.are_id");
        return $projects;
    }

    // * Método estático para buscar un proyecto por su ID, devolviendo el nombre del proyecto y el nombre del área.
    public static function search($id){
        $project = DB::select("SELECT projects.proj_id, projects.proj_name, areas.are_name,projects.are_id FROM projects
        INNER JOIN areas ON projects.are_id = areas.are_id
        WHERE projects.proj_id = $id");
        return $project[0];
    }
}
