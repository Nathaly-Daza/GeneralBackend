<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable; // Traits utilizados por el modelo

    protected $primaryKey = 'use_id'; // Clave primaria personalizada

    protected $fillable = [ // Atributos que se pueden asignar en masa
        'use_mail',
        'use_password',
        'use_photo',
        'use_status',
    ];

    protected $hidden = [ // Atributos ocultos al serializar el modelo
        'password', // Atributo 'password' no visible
        'remember_token', // Token de recordatorio no visible
    ];

    public $timestamps = false; // Indica si el modelo debe tener marcas de tiempo

    public static function filtredfortypeperson($column, $data)
    {
        if ($column == "use_status") {
            // Consulta los usuarios ordenados por columna especificada y filtrados por valor

            $user = User::orderBy($column, 'DESC')->where($column, $data)->take(50);
            $userIds = $user->pluck('use_id')->toArray(); // Obtiene los IDs de usuario filtrados

            // Busca las personas vinculadas a esos usuarios
            $personasVinculadas = Person::whereIn('use_id', $userIds)->take(50)->get();
            foreach ($personasVinculadas as $person) {

                // Consulta detallada de la persona utilizando su ID

                $persons = DB::select(" SELECT * FROM ViewPersons WHERE per_id = $person->use_id");
                // Aquí podrías manipular o procesar los datos de $detailedPerson según tus necesidades

            }
            return $persons; // Retorna la información detallada de la persona encontrada
        } else {
            // Si la columna especificada no es válida, retorna un mensaje de error

            return response()->json([
                'status' => False,
                'message' => "Invalid column"
            ], 400);
        }
    }
}
