<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Scholarship extends Model
{
    use HasFactory;

    // Define la clave primaria personalizada
    protected $primaryKey = 'sch_id';

    // Nombre de la tabla en la base de datos
    protected $table = "scholarships";

    // Atributos que se pueden asignar en masa
    protected $fillable = [
        'sch_name',
        'sch_description'
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;
}

