<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Pay_Times extends Model
{
    use HasFactory;

    // Nombre de la tabla asociada al modelo
    protected $table = 'pay_times';

    // Define la clave primaria personalizada
    protected $primaryKey = 'pay_tim_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'pay_tim_name',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;
}

