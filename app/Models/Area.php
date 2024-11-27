<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Area extends Model
{
    use HasFactory;

    // Definición de propiedades del modelo Area
    protected $primaryKey = 'are_id'; // Nombre de la clave primaria en la tabla 'areas'
    protected $fillable = [ // Campos que se pueden asignar de manera masiva
        'are_name', // Nombre del área
    ];
    public $timestamps = false; // Desactivar los timestamps created_at y updated_at
}

