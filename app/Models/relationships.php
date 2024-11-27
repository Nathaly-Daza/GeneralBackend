<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class relationships extends Model
{
    use HasFactory;

    //=========IMPORTANTE ADAPTAR AL MODELO=============
    // Define la clave primaria personalizada
    protected $primaryKey = 'rel_id';

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'rel_name',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;
}
