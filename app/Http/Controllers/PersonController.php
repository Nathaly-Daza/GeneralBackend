<?php

namespace App\Http\Controllers;

use App\Models\Person;
use App\Models\Student;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;


class PersonController extends Controller
{
    // Método para obtener todos los registros de personas
    public function index()
    {
        try {
            $persons = Person::select(); // Obtiene todos los registros de personas (probablemente debería ser Person::all() en lugar de select())
            return response()->json([
                'status' => true,
                'data' => $persons  // Retorna los datos obtenidos en formato JSON
            ], 200);
        } catch (\Throwable $th) {  // Captura cualquier excepción que ocurra
            return response()->json([
                'status' => false,
                'message' => "Error occurred while fetching elements"  // Retorna un mensaje de error si falla
            ], 500);
        }
    }

    // Método para obtener una persona por su id y tipo de documento
    public function show($id, $docTypeId)
    {
        try {
            $persons = Person::findByDocument($id, $docTypeId);  // Busca una persona por su documento y tipo de documento
            return response()->json([
                'status' => true,
                'data' => $persons  // Retorna los datos encontrados en formato JSON
            ], 200);
        } catch (\Throwable $th) {  // Captura cualquier excepción que ocurra
            return response()->json([
                'status' => false,
                'message' => "Error occurred while fetching elements"  // Retorna un mensaje de error si falla
            ], 500);
        }
    }
    // Método para obtener el perfil de una persona
    public function profile($proj_id, $use_id)
    {
        try {
            $persons = Person::findByper($use_id);  // Busca una persona por su id
            Controller::NewRegisterTrigger("Se ingreso al perfil de: " . $persons->per_name, 4, $use_id);  // Registra una acción en el sistema
            return response()->json([
                'status' => true,
                'data' => $persons  // Retorna los datos del perfil en formato JSON
            ], 200);
        } catch (\Throwable $th) {  // Captura cualquier excepción que ocurra
            return response()->json([
                'status' => false,
                'message' => "Error occurred while fetching elements"  // Retorna un mensaje de error si falla
            ], 500);
        }
    }
    // Método para actualizar los datos de una persona
    public function update(Request $request, $id)
    {
        $person = Person::find($id);  // Busca una persona por su id

        if ($person == null) {  // Si no se encuentra la persona
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The person requested is not found']  // Retorna un mensaje de error
            ], 400);
        } else {
            // Validación de los datos recibidos
            $documents = DB::select("SELECT doc_typ_id, per_document, per_id FROM persons");
            foreach ($documents as $document) {
                //Validación de la existencia del documento
                if ($document->per_document == $request->per_document && $document->doc_typ_id == $request->doc_typ_id && $document->per_id != $id) {
                    return response()->json([
                        'status' => false,
                        'message' => "The document you are trying to register already exists"  // Retorna un mensaje si el documento ya existe
                    ]);
                }
            }

            // Reglas de validación para actualizar los datos de la persona
            $rules = [
                'per_name' => 'required|min:1|max:255|regex:/^[a-zA-ZñÑáéíóúÁÉÍÓÚüÜ\s]+$/',
                'per_lastname' => 'required|min:1|max:255|regex:/^[a-zA-ZñÑáéíóúÁÉÍÓÚüÜ\s]+$/',
                'per_document' => 'required|min:1|max:999999999999999|regex:/^[a-zA-ZñÑ\s0-9]+$/',
                'per_expedition' => 'required|date|after_or_equal:per_birthdate|before_or_equal:now',
                'per_birthdate' => 'required|date|before_or_equal:now',
                'per_direction' => 'required|min:1|max:255|regex:/^(?=.*[a-zA-Z0-9])[\w\s\-\#\.]+$/',
                'civ_sta_id' => 'required|integer|exists:civil_states',
                'doc_typ_id' => 'required|integer|exists:document_types',
                'eps_id' => 'required|integer|exists:eps',
                'gen_id' => 'required|integer|exists:genders',
                'mul_id' => 'required|integer|exists:multiculturalisms',
                'per_rh' => 'required',
            ];

            // Validación de los datos recibidos con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            if ($validator->fails()) {  // Si falla la validación
                return response()->json([
                    'status' => false,
                    'message' => $validator->errors()->all()  // Retorna los mensajes de error de validación
                ]);
            } else {
                // Actualización de los datos de la persona
                $person->per_name = $request->per_name;
                $person->per_lastname = $request->per_lastname;
                $person->per_document = $request->per_document;
                $person->per_expedition = $request->per_expedition;
                $person->per_birthdate = $request->per_birthdate;
                $person->per_direction = $request->per_direction;
                $person->civ_sta_id = $request->civ_sta_id;
                $person->doc_typ_id = $request->doc_typ_id;
                $person->eps_id = $request->eps_id;
                $person->gen_id = $request->gen_id;
                $person->mul_id = $request->mul_id;
                $person->per_rh = $request->per_rh;
                $person->save();  // Guarda los cambios en la base de datos
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla persons del dato: $id con los datos: ", 1, $request->use_id);  // Registra una acción en el sistema
                return response()->json([
                    'status' => true,
                    'message' => "The person: " . $person->per_name . " has been updated successfully."  // Retorna un mensaje de éxito
                ], 200);
            }
        }
    }
    // Método para actualizar la contraseña de un usuario
    public function update_password(Request $request)
    {
        $person = User::find($request->use_id);  // Busca un usuario por su id

        if ($request->use_password != $person->use_password) {  // Verifica si la contraseña anterior coincide
            return response()->json([
                'status' => false,
                'message' => "The old password does not match"  // Retorna un mensaje de error si no coincide
            ]);
        }

        // Validación del nuevo password
        $rules = [
            'new_password' => 'required'
        ];

        // Validación de los datos recibidos con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        if ($validator->fails()) {  // Si falla la validación
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()  // Retorna los mensajes de error de validación
            ]);
        } else {
            if ($request->new_password == $person->use_password) {  // Verifica si la nueva contraseña es igual a la anterior
                return response()->json([
                    'status' => false,
                    'message' => "New password cannot be the same as the old password"  // Retorna un mensaje de error
                ]);
            } else {
                if ($request->new_password != $request->password_confirmation) {  // Verifica si la confirmación de la contraseña es correcta
                    return response()->json([
                        'status' => false,
                        'message' => "Invalid password confirmation"  // Retorna un mensaje de error
                    ]);
                }
                // Actualización de la contraseña
                $person->use_password = $request->new_password;
                $person->save();  // Guarda los cambios en la base de datos
                Controller::NewRegisterTrigger("se actualizo la contraseña del usuario: " . $person->use_mail, 4, $request->use_id);  // Registra una acción en el sistema
                return response()->json([
                    'status' => true,
                    'message' => "Password was successfully changed"  // Retorna un mensaje de éxito
                ]);
            }
        }
    }
    // Método para cambiar el estado de un usuario
    public function destroy(Request $request, $id)
    {
        $user = User::find($id);  // Busca un usuario por su id
        $newStatus = ($user->use_status == 1) ? 0 : 1;  // Cambia el estado del usuario

        $user->use_status = $newStatus;  // Actualiza el estado del usuario
        $user->save();  // Guarda los cambios en la base de datos

        Controller::NewRegisterTrigger("Se cambio el estado de un dato en la tabla persons", 4, $request->use_id);  // Registra una acción en el sistema

        return response()->json([
            'status' => true,
            'message' => 'User status updated successfully'  // Retorna un mensaje de éxito
        ]);
    }

    public function sendEmailReminder(Request $request)
    {
        $mail = new PHPMailer(true);  // Inicializa PHPMailer

        $user = DB::table("users")->where('use_mail', '=', $request->use_mail)->first();  // Busca un usuario por su correo electrónico

        if ($user == null) {  // Si no se encuentra el usuario
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the user you are looking for']  // Retorna un mensaje de error
            ], 400);
        } else {
            try {
                /* Configuración del servidor SMTP y envío de correo electrónico */
                $mail->SMTPDebug = 0;
                $mail->isSMTP();
                $mail->Host = env('MAIL_HOST');
                $mail->SMTPAuth = true;
                $mail->Username = env('MAIL_USERNAME');
                $mail->Password = env('MAIL_PASSWORD');
                $mail->SMTPSecure = env('MAIL_ENCRYPTION');
                $mail->Port = env('MAIL_PORT');
                $mail->setFrom(env('MAIL_FROM_ADDRESS'), env('MAIL_FROM_NAME'));
                $mail->addAddress($request->use_mail);
                $mail->isHTML(true);
                $mail->Subject = "Restauracion de Contraseña";
                $code = rand(100000, 999999);
                DB::statement("INSERT INTO reset_passwords (`res_pas_code`, `use_id`) VALUES ($code, $user->use_id);");

                // Cuerpo del correo electrónico
                $mail->Body = "
                    <!DOCTYPE html>
                    <html lang='es'>
                        <head>
                            <meta charset='utf-8'/>
                        </head>
                        <body>
                            <p>Estimado(a) Usuario:</p>
                            <p>Le confirmamos que ha cambiado de manera exitosa su contraseña. Puede dirigirse al siguiente enlace <a href='http://localhost:3000/resetPassword'>Restauracion de contraseña</a> e ingresar con su contraseña establecida</p>
                            <p>Tu codigo de seguridad es: {$code}</p>
                            <p>Este correo fue enviado automáticamente, agradecemos no responder este mensaje.</p>
                            <p>Gracias por su atención.</p>
                        </body>
                    </html>";

                if (!$mail->send()) {  // Intenta enviar el correo electrónico
                    return response()->json([
                        'status' => false,
                        'message' => "Email not sent."  // Retorna un mensaje de error si falla el envío
                    ]);
                } else {
                    return response()->json([
                        'status' => true,
                        'message' => "Email has been sent."  // Retorna un mensaje de éxito si el correo se envía correctamente
                    ]);
                }
            } catch (Exception $e) {
                return $e;  // Retorna la excepción si ocurre un error
            }
        }
    }

    // Método para restablecer la contraseña
    public function reset_password(Request $request)
    {
        $code = Person::reset_password($request);  // Llama al método para restablecer la contraseña

        if ($code == null) {  // Si el código no coincide
            return response()->json([
                'status' => false,
                'message' => "Code does not match"  // Retorna un mensaje de error
            ], 400);
        }

        // Validación del nuevo password
        $rules = [
            'new_password' => 'required'
        ];

        // Validación de los datos recibidos con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        if ($validator->fails()) {  // Si falla la validación
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()  // Retorna los mensajes de error de validación
            ]);
        } else {
            if ($request->new_password != $request->password_confirmation) {  // Verifica si la confirmación de la contraseña es correcta
                return response()->json([
                    'status' => false,
                    'message' => "Invalid password confirmation"  // Retorna un mensaje de error
                ], 400);
            }
            // Actualización de la contraseña
            $person = User::find($code->use_id);
            $person->use_password = $request->new_password;
            $person->save();  // Guarda los cambios en la base de datos

            Person::deleteCode($code);  // Elimina el código de restablecimiento de contraseña

            Controller::NewRegisterTrigger("se restauro la contraseña del usuario: " . $person->use_mail, 4, $person->use_id);  // Registra una acción en el sistema

            return response()->json([
                'status' => true,
                'message' => "Password was successfully changed"  // Retorna un mensaje de éxito
            ]);
        }
    }

    // Método para obtener una vista por documento
    public function viewForDocument(Request $request)
    {
        $person = Person::viewForDocument($request);  // Obtiene una vista por documento

        return response()->json([
            'status' => true,
            'data' => $person  // Retorna los datos obtenidos en formato JSON
        ], 200);
    }
    // Método para cambiar la contraseña de emergencia
    public function passwordEmergency(Request $request)
    {
        $person = Person::PasswordEmergency($request);  // Cambia la contraseña de emergencia

        $person->use_password = $request->use_password;  // Actualiza la contraseña

        $person->save();  // Guarda los cambios en la base de datos

        return response()->json([
            'status' => true,
            'data' => "The emergency password has been changed successfully."  // Retorna un mensaje de éxito
        ]);
    }
    // Método para obtener las últimas personas registradas
    public function lastPersons()
    {
        try {
            $person = Person::lastPersons();  // Obtiene las últimas personas registradas
            return response()->json([
                'status' => true,
                'data' => $person  // Retorna los datos obtenidos en formato JSON
            ], 200);
        } catch (\Throwable $th) {  // Captura cualquier excepción que ocurra
            return response()->json([
                'status' => false,
                'message' => $th  // Retorna un mensaje de error si falla
            ], 400);
        }
    }

    // Método para actualizar la foto de perfil de una persona
    public function updatePhoto(Request $request, $id)
    {
        $user = User::find($id);  // Busca un usuario por su id

        $image = $request->file('file');  // Obtiene la imagen recibida
        $image->move(public_path('images'), "$user->use_mail.jpg");  // Guarda la imagen en la carpeta de imágenes

        $imageUrl = base64_encode(asset('images/' . "$user->use_mail.jpg"));  // Genera la URL de la imagen

        $user->use_photo = $imageUrl;  // Actualiza la URL de la foto de perfil del usuario
        $user->save();  // Guarda los cambios en la base de datos

        return response()->json([
            'status' => true,
            'message' => "Image updated successfully"  // Retorna un mensaje de éxito
        ], 200);
    }

    // Método para filtrar personas por documento y tipo de documento
    public function filtredforDocument($id, $docTypeId)
    {
        try {
            $persons = Person::findByDocument($id, $docTypeId);  // Busca personas por documento y tipo de documento
            return response()->json([
                'status' => true,
                'data' => $persons  // Retorna los datos obtenidos en formato JSON
            ], 200);
        } catch (\Throwable $th) {  // Captura cualquier excepción que ocurra
            return response()->json([
                'status' => false,
                'message' => "Error occurred while fetching elements"  // Retorna un mensaje de error si falla
            ], 500);
        }
    }
    public function updateCoforInformation(Request $request)
    {
        if ($request->acc_administrator == 1) {  // Verifica si el usuario es administrador activo
            $rules = [
                'per_direction' => 'min:1|max:255|regex:/^(?=.*[a-zA-Z0-9])[\w\s\-\#\.]+$/',
                'loc_id' => 'exists:localities',
                'per_id' => 'exists:persons'
            ];

            // Validar los datos recibidos con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            if ($validator->fails()) {  // Si la validación falla, retorna un mensaje de error
                return response()->json([
                    'status' => false,
                    'message' => $validator->errors()->all()
                ]);
            } else {  // Si la validación es exitosa, procede a actualizar la información
                // Buscar y actualizar la persona
                $person = Person::find($request->per_id);
                $person->per_direction = $request->per_direction;

                // Si existe un estudiante asociado, actualizar la localidad y dirección
                $student = Student::find($request->stu_id);
                if ($student) {
                    $student->loc_id = $request->loc_id;
                    $person->save();
                    $student->save();
                }

                // Retornar una respuesta JSON indicando el éxito de la operación y los datos actualizados
                return response()->json([
                    'status' => true,
                    'person' => $person,
                    'student' => $student
                ]);
            }
        } else {  // Si el usuario no es administrador activo, retorna un mensaje de acceso denegado
            return response()->json([
                'status' => false,
                'message' => 'Access denied. This action can only be performed by active administrators.'
            ], 403);
        }
    }
}
