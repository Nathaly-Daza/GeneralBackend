<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class CivilStates extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'civil_states';

    // Clave primaria de la tabla
    protected $primaryKey = 'civ_sta_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'civ_sta_name',
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;
}

