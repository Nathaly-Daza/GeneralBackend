<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Vinculation_Type extends Model
{
    use HasFactory;

    protected $table = 'vinculation_types'; // Nombre de la tabla asociada al modelo

    protected $primaryKey = 'vin_typ_id'; // Clave primaria de la tabla

    protected $fillable = [ // Atributos que son asignables en masa
        'vin_typ_name',
    ];

    public $timestamps = false; // Deshabilita los timestamps automáticos
}
