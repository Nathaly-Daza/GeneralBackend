<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Student_types extends Model
{
    use HasFactory;

    // Define la clave primaria personalizada
    protected $primaryKey = 'stu_typ_id';

    // Nombre de la tabla en la base de datos
    protected $table = "students_types";

    // Atributos que se pueden asignar en masa
    protected $fillable = [
        'stu_typ_name',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;
}

