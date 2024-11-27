<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class Person extends Model
{
    use HasFactory;
    //=========IMPORTANTE ADAPTAR AL MODELO=============

    // Define la clave primaria personalizada
    protected $primaryKey = 'per_id';

    // Nombre de la tabla asociada al modelo
    protected $table = "persons";

    // Define los atributos que se pueden asignar en masa
    protected $fillable = [
        'per_name',
        'per_lastname',
        'per_document',
        'per_expedition',
        'per_birthdate',
        'per_direction',
        'civ_sta_id',
        'doc_typ_id',
        'eps_id',
        'gen_id',
        'con_id',
        'mul_id',
        'use_id',
        'per_rh',
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;

    // Método estático para seleccionar todas las personas desde la vista ViewPersons

    public static function select()
    {
        $persons = DB::select("SELECT * FROM ViewPersons");
        foreach ($persons as $person) {
            $person->use_photo = base64_decode($person->use_photo);
        }
        return $persons;
    }

    // Método estático para buscar personas por número de documento y tipo de documento

    public static function findByDocument($id, $docTypeId)
    {
        $persons = DB::select("SELECT * FROM ViewPersons WHERE per_document = '$id' AND doc_typ_id = '$docTypeId'");
        return $persons;
    }

    // Método estático para buscar una persona por ID

    public static function findByper($use_id)
    {
        $persons = DB::select("SELECT * FROM ViewPersons WHERE per_id = $use_id");
        $persons[0]->use_photo = base64_decode($persons[0]->use_photo);
        foreach ($persons as $person) {
            $mails = DB::table('mails')->where('per_id', '=', $person->per_id)->get();
            $telephones = DB::table('telephones')->where('per_id', '=', $person->per_id)->get();
            $contacts = DB::table('contacts')->where('per_id', '=', $person->per_id)->get();
            $medical_histories = DB::table('medical_histories')->where('per_id', '=', $person->per_id)->get();
            $person->mails = $mails;
            $person->telephones = $telephones;
            $person->contacts = $contacts;
            $person->medical_histories = $medical_histories;
        }
        return $persons[0];
    }

    // Método estático para obtener el código de restablecimiento de contraseña

    public static function reset_password($request)
    {
        $code = DB::select("SELECT * FROM reset_passwords WHERE res_pas_code = $request->res_pas_code");
        return $code[0];
    }

    // Método estático para eliminar un código de restablecimiento de contraseña

    public static function deleteCode($code)
    {
        $useId = $code->use_id;
        DB::select("DELETE FROM reset_passwords WHERE use_id = $useId");
    }

    // Método estático para ver información de persona por documento y tipo de documento

    public static function viewForDocument($request)
    {
        try {
            $person = DB::select("SELECT ViewPersons.* FROM ViewPersons
            WHERE ViewPersons.per_document = ? AND ViewPersons.doc_typ_id = ?", [$request->per_document, $request->doc_typ_id]);
            $mail = DB::table('mails')->where('per_id', '=', $person[0]->per_id)->get();
            $telephones = DB::table('telephones')->where('per_id', '=', $person[0]->per_id)->get();
            $contacts = DB::select("SELECT contacts.*, relationships.rel_name FROM contacts INNER JOIN relationships ON contacts.rel_id = relationships.rel_id WHERE per_id = ?", [$person[0]->per_id]);
            $medical_histories = DB::select("SELECT medical_histories.*, diseases.dis_name FROM medical_histories INNER JOIN diseases ON medical_histories.dis_id = diseases.dis_id WHERE per_id = ?", [$person[0]->per_id]);
            $person[0]->use_photo = base64_decode($person[0]->use_photo);
            $person[0]->mails = $mail;
            $person[0]->telephones = $telephones;
            $person[0]->contacts = $contacts;
            $person[0]->medical_histories = $medical_histories;
            return $person[0];
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => "Error occurred while found elements"
            ], 500);
        }
    }

    // Método estático para obtener las últimas 50 personas registradas

    public static function lastPersons()
    {
        $persons = DB::select("SELECT * FROM ViewPersons ORDER BY per_id DESC LIMIT 50");
        return $persons;
    }

    // Método estático para obtener información de usuario por correo electrónico para emergencias de contraseña

    public static function PasswordEmergency($request)
    {
        $person = DB::table('users')->where('use_mail', '=', $request->use_mail)->first();
        $person = User::find($person->use_id);
        return $person;
    }
}
