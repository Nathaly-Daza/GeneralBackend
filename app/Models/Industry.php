<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Industry extends Model
{
    use HasFactory;
    // Nombre de la tabla en la base de datos.
    protected $table = 'industries';
    // Nombre de la clave primaria.
    protected $primaryKey = 'ind_id';
    //  Los atributos que se pueden asignar en masa.
    protected $fillable = ['ind_name'];
    //  Indica si el modelo debe registrar automáticamente las marcas de tiempo.
    public $timestamps = false;
}
