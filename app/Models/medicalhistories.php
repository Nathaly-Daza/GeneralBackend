<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class medicalhistories extends Model
{
    use HasFactory;

    // Define el nombre de la clave primaria
    protected $primaryKey = 'med_his_id';

    // Nombre de la tabla asociada al modelo
    protected $table = "medical_histories";

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'per_id',
        'dis_id',
        'med_his_status',
    ];

    // Indica si el modelo debe tener marcas de tiempo
    public $timestamps = false;

    // * Retorna todos los registros de historias médicas con información adicional de la persona y la enfermedad.

    public static function select(){
        $medicalHistory = DB::select("SELECT medical_histories.med_his_id,medical_histories.med_his_status,medical_histories.per_id, medical_histories.dis_id, persons.per_name, persons.per_lastname, persons.per_document,persons.doc_typ_id,document_types.doc_typ_name, diseases.dis_name
        FROM medical_histories
        INNER JOIN persons ON medical_histories.per_id = persons.per_id
        INNER JOIN diseases ON medical_histories.dis_id = diseases.dis_id
        INNER JOIN document_types ON persons.doc_typ_id = document_types.doc_typ_id");
        return $medicalHistory;
    }

    // * Busca una historia médica específica por su ID.
    public static function search($id){
        $medicalHistory = DB::select("SELECT medical_histories.med_his_id,medical_histories.per_id, medical_histories.dis_id, persons.per_name, persons.per_lastname, persons.per_document,persons.doc_typ_id,document_types.doc_typ_name, diseases.dis_name
        FROM medical_histories
        INNER JOIN persons ON medical_histories.per_id = persons.per_id
        INNER JOIN diseases ON medical_histories.dis_id = diseases.dis_id
        INNER JOIN document_types ON persons.doc_typ_id = document_types.doc_typ_id
        WHERE $id = medical_histories.med_his_id");
        return $medicalHistory[0];
    }
}
