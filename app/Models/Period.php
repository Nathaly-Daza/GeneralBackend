<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Period extends Model
{
    use HasFactory;

    // Nombre de la tabla asociada al modelo
    protected $table = 'periods';

    // Define la clave primaria personalizada
    protected $primaryKey = 'peri_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'peri_name',
        'peri_start',
        'peri_end',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;
}

