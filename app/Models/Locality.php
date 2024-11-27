<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Locality extends Model
{
    use HasFactory;
    //=========IMPORTANTE ADAPTAR AL MODELO=============

    // Define el nombre de la clave primaria
    protected $primaryKey = 'loc_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'loc_name',
    ];

    // Indica si el modelo debe tener marcas de tiempo
    public $timestamps = false;
}
