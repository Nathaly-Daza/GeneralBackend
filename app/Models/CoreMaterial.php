<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class CoreMaterial extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = "core_material";

    // Clave primaria de la tabla
    protected $primaryKey = "cor_mat_id";

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'cor_mat_name',
        'cor_mat_semester',
        'car_id'
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;

    // * Método estático para seleccionar todos los materiales de núcleo con información relacionada a la carrera.
    public static function select() {
        $coreMaterials = DB::table('core_material')
        ->join('careers', 'careers.car_id', '=', 'core_material.car_id')
        ->select('core_material.cor_mat_id', 'core_material.cor_mat_name', 'core_material.cor_mat_semester', 'careers.car_id', 'careers.car_name')->get();
        return $coreMaterials;
    }

    // * Método estático para encontrar un material de núcleo por su ID.
    public static function findOne($id) {
        $coreMaterials = DB::table('core_material')
        ->where('cor_mat_id', $id)
        ->get();
        return $coreMaterials;
    }
}
