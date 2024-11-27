<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Activity extends Model
{
    use HasFactory;

    // Definición de propiedades del modelo Activity
    protected $table = 'activities'; // Nombre de la tabla en la base de datos
    protected $primaryKey = 'acti_id'; // Nombre de la clave primaria
    protected $fillable = [ // Campos que se pueden asignar de manera masiva
        'acti_name',
        'acti_code'
    ];
    public $timestamps = false; // Desactivar los timestamps created_at y updated_at
}

