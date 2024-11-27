<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Genders extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'genders';

    // Clave primaria de la tabla
    protected $primaryKey = 'gen_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'gen_name',
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;
}

