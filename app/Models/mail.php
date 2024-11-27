<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class mail extends Model
{
     // Define el nombre de la clave primaria
     protected $primaryKey = 'mai_id';

     // Define los atributos que se pueden asignar en masa
     protected $fillable = [
         'mai_mail',
         'mai_description',
         'per_id'
     ];

     // Indica si el modelo debe tener marcas de tiempo
     public $timestamps = false;

    //  * Retorna todos los correos con información adicional de la persona y el tipo de documento.

    public static function select(){
        $mail = DB::select("SELECT mails.mai_id, mails.mai_mail, mails.mai_description, mails.per_id,persons.per_name,persons.per_lastname,persons.per_document,persons.doc_typ_id,document_types.doc_typ_name
        FROM mails
        INNER JOIN persons ON mails.per_id = persons.per_id
        INNER JOIN document_types ON persons.doc_typ_id = document_types.doc_typ_id");
        return $mail;
    }

    // * Busca un correo específico por su ID de persona.

    
    public static function search($id){
        $mail = DB::select("SELECT mails.mai_id, mails.mai_mail, mails.mai_description, mails.per_id,persons.per_name,persons.per_lastname,persons.per_document,persons.doc_typ_id,document_types.doc_typ_name
        FROM mails
        INNER JOIN persons ON mails.per_id = persons.per_id
        INNER JOIN document_types ON persons.doc_typ_id = document_types.doc_typ_id WHERE $id = mails.per_id");
        return $mail[0];
    }
}

