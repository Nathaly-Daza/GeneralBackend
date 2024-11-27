<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Pay_Types extends Model
{
    use HasFactory;

    // Nombre de la tabla asociada al modelo
    protected $table = 'pay_types';

    // Define la clave primaria personalizada
    protected $primaryKey = 'pay_typ_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'pay_typ_name',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;
}

