<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Career_Types extends Model
{
    use HasFactory;

    // Definición de propiedades del modelo Career_Types
    protected $table = 'career_types'; // Nombre de la tabla en la base de datos
    protected $primaryKey = 'car_typ_id'; // Nombre de la clave primaria en la tabla
    protected $fillable = [ // Campos que se pueden asignar de manera masiva
        'car_typ_name', // Nombre del tipo de carrera
    ];
    public $timestamps = false; // Desactivar los timestamps created_at y updated_at
}

