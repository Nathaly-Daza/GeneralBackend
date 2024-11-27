<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class Contact extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'contacts';

    // Clave primaria de la tabla
    protected $primaryKey = 'con_id';

    // Campos que pueden ser llenados mediante asignación en masa (mass assignment)
    protected $fillable = [
        'con_name',
        'con_mail',
        'con_telephone',
        'rel_id',
        'per_id'
    ];

    // Desactivar timestamps created_at y updated_at
    public $timestamps = false;

    //  Método estático para seleccionar todos los contactos con información relacionada.
    //  Utiliza consultas SQL directas para obtener datos específicos de la base de datos.
    public static function select()
    {
        $contacts = DB::select("SELECT contacts.con_id, contacts.con_name, contacts.con_mail, contacts.con_telephone, relationships.rel_name,contacts.per_id, persons.per_name,persons.per_lastname,persons.per_document,persons.doc_typ_id,document_types.doc_typ_name,contacts.rel_id
        FROM contacts
        INNER JOIN relationships ON contacts.rel_id = relationships.rel_id
        INNER JOIN persons ON contacts.per_id = persons.per_id
        INNER JOIN document_types ON persons.doc_typ_id = document_types.doc_typ_id");
        return $contacts;
    }

    //  Método estático para buscar un contacto específico por su ID.
    //  Utiliza una consulta SQL directa para obtener datos específicos de la base de datos.

    public static function search($id)
    {
        $contacts = DB::select("SELECT contacts.con_id, contacts.con_name, contacts.con_mail, contacts.con_telephone, relationships.rel_name,contacts.per_id, persons.per_name,persons.per_lastname,persons.per_document,persons.doc_typ_id,document_types.doc_typ_name,contacts.rel_id
        FROM contacts
        INNER JOIN relationships ON contacts.rel_id = relationships.rel_id
        INNER JOIN persons ON contacts.per_id = persons.per_id
        INNER JOIN document_types ON persons.doc_typ_id = document_types.doc_typ_id WHERE $id = contacts.con_id");
        return $contacts[0];
    }
}
