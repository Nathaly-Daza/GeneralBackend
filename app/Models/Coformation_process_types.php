<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Coformation_process_types extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'coformation_process_types';

    // Clave primaria de la tabla
    protected $primaryKey = 'cof_pro_typ_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'cof_pro_typ_name',
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;
}

