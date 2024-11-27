<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Career extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'careers';

    // Clave primaria de la tabla
    protected $primaryKey = 'car_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'car_name',
        'car_typ_id'
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;

    // Método estático para seleccionar todos los registros de carreras
    // con sus tipos de carrera relacionados.
    // Utiliza un join con la tabla career_types.
    public static function select()
    {
        $careers = Career::join('career_types', 'careers.car_typ_id', '=', 'career_types.car_typ_id')
            ->select('careers.car_id', 'careers.car_name', 'career_types.car_typ_id', 'career_types.car_typ_name')
            ->get();

        return $careers;
    }
    //  Método estático para buscar una carrera por su ID.
    //  Retorna solo el nombre de la carrera y el nombre del tipo de carrera asociado.
    public static function search($id)
    {
        $careers = Career::join('career_types', 'careers.car_typ_id', '=', 'career_types.car_typ_id')
            ->select('careers.car_name', 'career_types.car_typ_name')
            ->where('careers.car_id', '=', $id)
            ->first();
        return $careers;
    }
}
