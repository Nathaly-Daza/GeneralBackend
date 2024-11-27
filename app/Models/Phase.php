<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Phase extends Model
{
    use HasFactory;

    // Nombre de la tabla asociada al modelo
    protected $table = 'phases';

    // Define la clave primaria personalizada
    protected $primaryKey = 'pha_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'pha_phase',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;
}
