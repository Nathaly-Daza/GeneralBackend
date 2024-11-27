<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class Position extends Model
{
    use HasFactory;
    //=========IMPORTANTE ADAPTAR AL MODELO=============

    // Nombre de la tabla asociada al modelo
    protected $table = 'positions';

    // Define la clave primaria personalizada
    protected $primaryKey = 'pos_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'pos_name',
        'are_id',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;

    // * Método estático para seleccionar todas las posiciones con el nombre del área correspondiente.
    public static function select(){
        $positions = DB::select("SELECT positions.pos_name, positions.pos_id, areas.are_name, positions.are_id FROM positions
        INNER JOIN areas ON positions.are_id = areas.are_id");
        return $positions;
    }

    // * Método estático para buscar una posición por su ID, devolviendo el nombre de la posición y el nombre del área.
    
    public static function search($id){
        $position = DB::select("SELECT positions.pos_name, positions.pos_id, areas.are_name,positions.are_id FROM positions
        INNER JOIN areas ON positions.are_id = areas.are_id
        WHERE $id = positions.pos_id ");
        return $position[0];
    }
}
