<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Contact_Companies_Types extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'contact_companies_types';

    // Clave primaria de la tabla
    protected $primaryKey = 'con_com_typ_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'con_com_typ_name'
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;
}

