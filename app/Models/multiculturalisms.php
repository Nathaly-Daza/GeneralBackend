<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class multiculturalisms extends Model
{
    //=========IMPORTANTE ADAPTAR AL MODELO=============
    // Define la clave primaria personalizada
    protected $primaryKey = 'mul_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'mul_name',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;

    use HasFactory;
}
