<?php

namespace App\Http\Controllers;

use App\Models\Contact;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;


class ContactController extends Controller
{
    // Método para listar todos los contactos
    public function index()
    {
        try {

            // Obtener todos los registros de la tabla 'contacts'
            $contacts = Contact::select();
            return response()->json([
                'status' => true,
                'data' => $contacts
            ], 200);
        } catch (\Throwable $th) {

            // Manejar errores y devolver un mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }

    // Método para crear un nuevo contacto
    public function store(Request $request)
    {
        // Reglas de validación para los campos de entrada
        $rules = [
            'con_name' => 'required|string|min:1|max:250|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'con_mail' => 'required|string|max:255|regex:/^[a-zA-Z0-9]+([-.]?[a-zA-Z0-9]+)*@[a-zA-Z0-9]+([-.]?[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$/',
            'con_telephone' => ['required', 'regex:/^([0-9\s\-\+\(\)]*)$/', 'min:7', 'max:15'],
            'rel_id' => 'required|integer|exists:relationships',
            'per_id' => 'required|integer|exists:persons',
            'use_id' => 'required|integer|exists:users'
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

             // Crear un nuevo registro en la tabla 'contacts'
            $contact = new Contact($request->input());
            $contact->save();

            // Registrar el evento de creación
            Controller::NewRegisterTrigger("Se creo un registro en la tabla Contact : $request->con_name, $request->con_relationship, $request->con_mail, $request->con_telephone ", 3, $request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => True,
                'message' => "The contact: " . $contact->con_name . " has been crated successfully.",
                'data' => $contact->con_id
            ], 200);
        }
    }

    // Método para mostrar un contacto específico
    public function show($id)
    {

        // Buscar el contacto por ID
        $contacts = Contact::search($id);

        // Si no se encuentra, devolver un mensaje de error
        if ($contacts == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'the contact requested not found']
            ], 400);
        } else {

            // Devolver el contacto en formato JSON
            return response()->json([
                'status' => true,
                'data' => $contacts
            ]);
        }
    }

    // Método para actualizar un contacto
    public function update(Request $request, $id)
    {

        // Buscar el contacto por ID
        $contact = Contact::find($id);

         // Si no se encuentra, devolver un mensaje de error
        if ($contact == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'the contact requested not found']
            ], 400);
        } else {

            // Reglas de validación para los campos de entrada
            $rules = [
                'con_name' => 'required|string|min:1|max:250|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'con_mail' => 'required|min:4|regex:/^[a-zA-Z0-9_]+([.?_¿¡!,a-zA-Z0-9_]+)*@[a-zA-Z0-9_]+([.][a-zA-Z0-9_]+)*[.][a-zA-Z]{2,5}/',
                'con_telephone' => 'required|min:7|max:15|regex:/^[0-9\s\-\+\(\)]*$/',
                'rel_id' => 'required|integer|exists:relationships',
                'per_id' => 'required|integer|exists:persons',
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

                // Actualizar los datos del contacto
                $contact->con_name = $request->con_name;
                $contact->con_mail = $request->con_mail;
                $contact->con_telephone = $request->con_telephone;
                $contact->rel_id = $request->rel_id;
                $contact->per_id = $request->per_id;
                $contact->save();

                // Registrar el evento de actualización
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla Contact del dato: $id con los datos: $request->con_name, $request->con_relationship, $request->con_mail, $request->con_telephone ", 1, $request->use_id);
                // Devolver un mensaje de éxito en formato JSON
                return response()->json([
                    'status' => True,
                    'message' => "The contact: " . $contact->con_name . " has been updated successfully."
                ], 200);
            }
        }
    }

    // Método para eliminar un contacto (actualmente no disponible)
    public function destroy(contact $contacts)
    {
        return response()->json([
            'status' => false,
            'message' => "Function not available"
        ], 400);
    }
}
