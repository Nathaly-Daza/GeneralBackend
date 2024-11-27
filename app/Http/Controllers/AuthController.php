<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Person;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

    // Método para iniciar sesión
    public function login(Request $request, $proj_id)
    {
        // Reglas de validación para los campos de entrada
        $rules = [
            'use_mail' => 'required|min:1|max:250|email',
            'use_password' => 'required|min:1|max:150|string'
        ];

        // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla, devolver los errores en formato JSON
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ], 400);
        } else {

            // Buscar el usuario por correo electrónico
            $user = DB::table('users')->where('use_mail', '=', $request->use_mail)->first();

            // Si el usuario no existe, devolver un mensaje de error
            if ($user == null) {
                return response()->json([
                    "status" => false,
                    "message" => "The user who is trying to login does not exist"
                ], 401);
            }

            // Verificar si la contraseña es correcta
            if ($user->use_password == $request->use_password) {

                // Encontrar el usuario por ID
                $user = User::find($user->use_id);

                // Obtener el ID del proyecto. Con un ternario, si no se proporciona, se usará el ID de la aplicación
                $project_id = ($request->proj_id === null) ? env('APP_ID') : $request->proj_id;

                // Buscar el estado de acceso del usuario al proyecto
                $access = DB::select("SELECT access.acc_status FROM access WHERE use_id = $user->use_id AND proj_id = $project_id");

                //En un ternario, si el acceso está vacio, se le asigna el acceso 2, de otra forma mantiene su acceso
                $acceso = ($access == null) ? 2 : $access[0]->acc_status;
                $use_status = $user->use_status;

                // Verificar si el usuario tiene acceso. Debe tener acceso si o si en el proyecto general
                if (($access == null && ($proj_id == 6||$proj_id==2 || $proj_id == 1)) || $acceso == 0 || $use_status == 0) {
                    return response()->json([
                        'status' => False,
                        'message' => "The user: " . $user->use_mail . " has no access."
                    ], 401);
                }

                // Si el acceso es 2, establecerlo a 0 (sin acceso)
                $acceso = ($acceso == 2) ? 0 : $acceso;

                // Se busca si el usuario ya tiene un token activo y se almacena
                $tokens = DB::table('personal_access_tokens')->where('tokenable_id', '=', $user->use_id)->get();

                //Se busca el estudiante relacionado el usuario
                $student = DB::table('viewStudents')->where('per_id', '=', $user->use_id)->get();

                //Con un ternario se almacena el id del primer estudiante si se encontró previamente uno, de otra forma se almacena null
                $stu_id = ($student != "[]") ? $student[0]->stu_id : null;

                // Verifica si el usuario ya tiene un token activo
                if ($tokens != "[]") {
                    return response()->json([
                        'status' => false,
                        'message' => "This user already has an active session"
                    ], 401);
                }


                $project_id = ($request->proj_id === null) ? env('APP_ID') : $request->proj_id;
                $person = DB::table('ViewPersons')->where('use_id', '=', $user->use_id)->first();

                // Registrar el evento de inicio de sesión
                Controller::NewRegisterTrigger("Se logeo un usuario: $user->use_mail", 4, $user->use_id);


                // Devolver los datos de inicio de sesión en formato JSON
                return response()->json([
                    'status' => True,
                    'message' => "User login successfully",
                    'use_id' => $user->use_id,
                    'per_document' => $person->per_document,
                    'stu_id' => $stu_id,
                    'token' => $user->createToken('API TOKEN')->plainTextToken,
                    'acc_administrator' => $acceso
                ], 200);
            } else {

                // Si la contraseña es incorrecta, devolver un mensaje de error
                return response()->json([
                    'status' => False,
                    'message' => "Invalid email or password"
                ], 401);
            }
        }
    }

    // Método para registrar un nuevo usuario
    public function register($use_id, Request $request)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'use_mail' => 'required|min:1|max:250|email|unique:users|regex:/^[a-zñA-ZÑ]+[a-zñA-ZÑ._-]*@uniempresarial\.edu\.co$/',
            'use_password' => 'required|min:1|max:150|string',
            'per_name' => 'required|min:1|max:150|string|regex:/^[a-zA-ZñÑáéíóúÁÉÍÓÚüÜ\s]+$/',
            'per_lastname' => 'required|min:1|max:100|string|regex:/^[a-zA-ZñÑáéíóúÁÉÍÓÚüÜ\s]+$/',
            'per_document' => 'required|max:999999999999999|regex:/^[a-zA-ZñÑ\s0-9]+$/',
            'per_expedition' => 'required|date',
            'per_birthdate' => 'required|date',
            'per_direction' => 'required|min:1|max:255|string|regex:/^(?=.*[a-zA-Z0-9])[\w\s\-#\.]+$/',
            'per_rh' => 'required|min:1|max:3|string',
            'civ_sta_id' => 'required|integer|exists:civil_states',
            'doc_typ_id' => 'required|integer|exists:document_types',
            'eps_id' => 'required|integer|exists:eps',
            'gen_id' => 'required|integer|exists:genders',
            'mul_id' => 'required|integer|exists:multiculturalisms',
        ];


        // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla, devolver los errores en formato JSON
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {

            // Verificar si el documento ya existe en la base de datos
            $documents = DB::select("SELECT doc_typ_id, per_document FROM persons");
            foreach ($documents as $document) {
                if ($document->per_document == $request->per_document && $document->doc_typ_id == $request->doc_typ_id) {
                    return response()->json([
                        'status' => False,
                        'message' => "The document you are trying to register already exists"
                    ]);
                }
            }

            // Crear un nuevo usuario
            $user = User::create([
                'use_mail' => $request->use_mail,
                'use_password' => $request->use_password,
                'use_photo' => 'aHR0cHM6Ly91cGxvYWQud2lraW1lZGlhLm9yZy93aWtpcGVkaWEvY29tbW9ucy8zLzM5L0xPR09fVU5JVkVSU0lEQURfVU5JRU1QUkVTQVJJQUxfVkVSVElDQUwucG5n',
                'use_status' => 1
            ]);
            $user->save();

            // Crear una nueva persona asociada al usuario
            $person = Person::create([
                'per_name' => $request->per_name,
                'per_lastname' => $request->per_lastname,
                'per_document' => $request->per_document,
                'per_expedition' => $request->per_expedition,
                'per_birthdate' => $request->per_birthdate,
                'per_direction' => $request->per_direction,
                'per_rh' => $request->per_rh,
                'civ_sta_id' => $request->civ_sta_id,
                'doc_typ_id' => $request->doc_typ_id,
                'eps_id' => $request->eps_id,
                'gen_id' => $request->gen_id,
                'mul_id' => $request->mul_id,
                'use_id' => $user->use_id,
            ]);
            $person->save();

            // Registrar el evento de registro
            Controller::NewRegisterTrigger("Se Registro un usuario: $request->per_name", 3, $use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => True,
                'message' => "User created successfully",
            ], 200);
        }
    }

    // Método para cerrar sesión
    public function logout(Request $id)
    {
        // Eliminar todos los tokens de acceso del usuario
        $tokens = DB::table('personal_access_tokens')->where('tokenable_id', '=', $id->use_id)->delete();
        return response()->json([
            'status' => true,
            'message' => "logout success."
        ]);
    }

    // Método para subir un archivo CSV
    public function uploadFile(Request $request)
    {

        // Verificar si la solicitud contiene un archivo
        if ($request->hasFile('file')) {
            $file = $request->file('file');

             // Almacenar el archivo en la carpeta 'csv'
            $file->storeAs('csv', $file->getClientOriginalName());

            // Leer los datos del archivo CSV
            $csvData = array_map('str_getcsv', file($file->path()));

            $csvVariable = [];
            foreach ($csvData as $row) {
                $csvVariable[] = [
                    'use_mail' => $row[0],
                ];
            }

            // Devolver los datos del archivo CSV en formato JSON
            return $csvVariable;
        }

        // Si no se encuentra un archivo en la solicitud, devolver un mensaje de error
        return response()->json(['error' => 'No CSV file found in request'], 400);
    }
}
