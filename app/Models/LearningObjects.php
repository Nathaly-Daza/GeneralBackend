<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class LearningObjects extends Model
{
    use HasFactory;
    // * Nombre de la tabla en la base de datos.
    protected $table = "learning_objects";
    // * Nombre de la clave primaria.
    protected $primaryKey = "lea_obj_id";
    // * Los atributos que se pueden asignar en masa.
    protected $fillable = [
        'lea_obj_object',
        'cor_mat_id',

    ];
    // * Indica si el modelo debe registrar automáticamente las marcas de tiempo.
    public $timestamps = false;

    // * Método para obtener todos los objetos de aprendizaje con información relacionada.
    public static function select() {
        $learningObjects = DB::table('learning_objects as le')
        ->join("core_material as co",'co.cor_mat_id','=','le.cor_mat_id')
        ->select('le.*', 'co.*')
        ->get();
        return $learningObjects;
    }
    
    // * Método para encontrar un objeto de aprendizaje por su ID con información relacionada.
    public static function findOne($id) {
        $learningObjects = DB::table('learning_objects')
        ->join("core_material as co",'co.cor_mat_id','=','le.cor_mat_id')
        ->select('le.*', 'co.*')
        ->where('lea_obj_id', $id)
        ->get();
        return $learningObjects;
    }
}
