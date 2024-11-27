<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class telephone extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'telephones';

    // Nombre de la clave primaria en la tabla
    protected $primaryKey = 'tel_id';

    // Atributos que se pueden asignar en masa
    protected $fillable = [
        'tel_number',
        'tel_description',
        'per_id',
    ];

    // Indica si el modelo debe tener marcas de tiempo
    public $timestamps = false;

    // Método para seleccionar todos los teléfonos con información adicional de la persona y tipo de documento

    public static function select()
    {
        $telephone = DB::select("SELECT telephones.tel_id, telephones.tel_number, telephones.tel_description, telephones.per_id, persons.per_name,persons.per_lastname ,persons.doc_typ_id,document_types.doc_typ_name, per_document
        FROM telephones
        INNER JOIN persons ON telephones.per_id = persons.per_id
        INNER JOIN document_types ON persons.doc_typ_id = document_types.doc_typ_id ");
        return $telephone;
    }

    // Método para buscar un teléfono por ID de persona


    public static function search($id)
    {
        $telephone = DB::select("SELECT telephones.tel_id, telephones.tel_number, telephones.tel_description, telephones.per_id, persons.per_name,persons.per_lastname,persons.doc_typ_id,document_types.doc_typ_name, per_document
        FROM telephones
        INNER JOIN persons ON telephones.per_id = persons.per_id
        INNER JOIN document_types ON persons.doc_typ_id = document_types.doc_typ_id  WHERE $id = telephones.per_id");
        return $telephone[0];
    }
}
