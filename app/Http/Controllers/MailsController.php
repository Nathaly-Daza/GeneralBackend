<?php

namespace App\Http\Controllers;

use App\Models\mail;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class MailsController extends Controller
{
    public function index()
    {
        try {
            // Intentar obtener todos los correos electrónicos
            $mail = mail::select();

            // Devolver una respuesta JSON con los correos electrónicos obtenidos
            return response()->json([
                'status' => true,
                'data' => $mail
            ], 200);
        } catch (\Throwable $th) {

            // Manejar errores y devolver una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }
    public function store(Request $request)
    {
        // Definir reglas de validación para los datos de entrada
        $rules = [
            'mai_mail' => ['required', 'min:4', 'regex:/^[a-zA-Z0-9]+([-_.]?[a-zA-Z0-9]+)*@[a-zA-Z0-9]+([-_.]?[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$/'],
            'mai_description' => 'string | max:255',
            'per_id' => 'required|integer|exists:persons',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada
        $validator = Validator::make($request->input(), $rules);

        // Devolver una respuesta JSON con los errores de validación si falla la validación
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {

            // Crear una nueva instancia de Mail con los datos proporcionados
            $mail = new Mail($request->input());
            $mail->save();

            // Registrar la acción en un sistema de seguimiento
            Controller::NewRegisterTrigger("Se realizó una inserción de datos en la tabla mails", 3, $request->use_id);

            // Devolver una respuesta JSON indicando que el correo electrónico ha sido creado exitosamente
            return response()->json([
                'status' => True,
                'message' => "The mail: " . $mail->mai_mail . " has been added succesfully.",
                'data' => $mail->mai_id
            ], 200);
        }
    }

    // Método para mostrar un correo electrónico específico
    public function show($id)
    {

        // Buscar un correo electrónico por su ID
        $mail = mail::search($id);
        if ($mail == null) {

            // Devolver un mensaje de error si no se encuentra el correo electrónico
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find mail you are looking for']
            ], 400);
        } else {

            // Devolver una respuesta JSON con el correo electrónico encontrado
            return response()->json([
                'status' => true,
                'data' => $mail
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {

        // Buscar el correo electrónico por su ID
        $mail = Mail::find($id);
        if ($mail == null) {

            // Devolver un mensaje de error si el correo electrónico no se encuentra
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find required mail']
            ], 400);
        } else {

            // Definir reglas de validación para los datos de entrada
            $rules = [
                'mai_mail' => 'required|string|max:255|regex:/^[a-zA-Z0-9]+([-_.]?[a-zA-Z0-9]+)*@[a-zA-Z0-9]+([-_.]?[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$/',
                'mai_description' => 'string|max:255',
                'per_id' => 'required|integer|exists:persons',
                'use_id' => 'required|integer|exists:users'
            ];

            // Validar los datos de entrada
            $validator = Validator::make($request->input(), $rules);

            // Devolver una respuesta JSON con los errores de validación si falla la validación
            if ($validator->fails()) {
                return response()->json([
                    'status' => False,
                    'message' => $validator->errors()->all()
                ], 400);
            } else {

                // Actualizar el correo electrónico con los datos proporcionados
                $mail->mai_mail = $request->mai_mail;
                $mail->mai_description = $request->mai_description;
                $mail->per_id = $request->per_id;
                $mail->save();

                 // Registrar la acción en un sistema de seguimiento
                Controller::NewRegisterTrigger("Se realizó una actualización de datos en la tabla mails", 1, $request->use_id);

                // Devolver una respuesta JSON indicando que el correo electrónico ha sido actualizado exitosamente
                return response()->json([
                    'status' => True,
                    'message' => "The mail " . $mail->mai_mail . " has been updated succesfully."
                ], 200);
            }
        }
    }
    public function destroy(Mail $mail)
    {
        // Devolver una respuesta JSON indicando que la función no está disponible para eliminar un correo electrónico
        return response()->json([
            'status' => false,
            'message' => "You have no permission to delete this"
        ], 400);
    }
}
