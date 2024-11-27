<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class DocumentTypes extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'document_types';

    // Clave primaria de la tabla
    protected $primaryKey = 'doc_typ_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'doc_typ_name',
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;
}

