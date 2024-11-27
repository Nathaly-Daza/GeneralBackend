<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Diseases extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'diseases';

    // Clave primaria de la tabla
    protected $primaryKey = 'dis_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'dis_name',
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;
}

