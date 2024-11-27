<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class Covenant_types extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'covenant_types';

    // Clave primaria de la tabla
    protected $primaryKey = 'cov_typ_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'cov_typ_name',
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;
}

