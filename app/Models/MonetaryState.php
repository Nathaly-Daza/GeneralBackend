<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class MonetaryState extends Model
{
        //=========IMPORTANTE ADAPTAR AL MODELO=============

    use HasFactory;

    // Define la clave primaria personalizada
    protected $primaryKey = "mon_sta_id";

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'mon_sta_name'
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;
}

