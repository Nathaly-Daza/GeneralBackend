<?php

namespace App\Http\Controllers;

use App\Models\Contact_Companies_Types;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class ContactCompaniesTypesController extends Controller
{
    // Método para listar todos los tipos de contactos de empresas
    public function index()
    {
        try {
            // Obtener todos los registros de la tabla 'contact_companies_types'
            $contact_companies_types = Contact_Companies_Types::all();
            return response()->json([
                'status' => true,
                'data' => $contact_companies_types,
            ], 200);
        } catch (\Throwable $th) {

            // Manejar errores y devolver un mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }

    // Método para crear un nuevo tipo de contacto de empresa
    public function store(Request $request)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'con_com_typ_name' => 'required|unique:contact_companies_types|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
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

            // Crear un nuevo registro en la tabla 'contact_companies_types'
            $contact_companies_types = new Contact_Companies_Types($request->input());
            $contact_companies_types->save();

            // Registrar el evento de creación
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla contact companies types", 3, $request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => true,
                'message' => "The process '" . $contact_companies_types->con_com_typ_name . "' has been added succesfully."
            ], 200);
        }
    }

    // Método para mostrar un tipo de contacto de empresa específico
    public function show($contact_Companies_Types)
    {

        // Buscar el tipo de contacto de empresa por ID
        $contact_companies_type = Contact_Companies_Types::find($contact_Companies_Types);

        // Si no se encuentra, devolver un mensaje de error
        if (!$contact_companies_type) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the contact companies types you are looking for'],
            ], 400);
        } else {

            // Devolver el tipo de contacto de empresa en formato JSON
            return response()->json([
                'status' => true,
                'data' => $contact_companies_type,
            ], 200);
        }
    }

    // Método para actualizar un tipo de contacto de empresa
    public function update(Request $request, $contact_Companies_Types)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'con_com_typ_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Validar que el nombre del tipo de contacto de empresa no exista ya en otro registro
        $validate = Controller::validate_exists($request->con_com_typ_name, 'contact_companies_types', 'con_com_typ_name', 'con_com_typ_id', $contact_Companies_Types);

        // Si la validación falla o el nombre ya existe, devolver un mensaje de error
        if ($validator->fails() || $validate == 0) {
            $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
            return response()->json([
                'status' => False,
                'message' => $msg
            ]);
        } else {
            // Buscar el tipo de contacto de empresa por ID
            $contact_companies_type = Contact_Companies_Types::find($contact_Companies_Types);

            // Actualizar el registro en la tabla 'contact_companies_types'
            $contact_companies_type->con_com_typ_name = $request->con_com_typ_name;
            $contact_companies_type->save();

            // Registrar el evento de actualización
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla contact companies types", 3, $request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => true,
                'data' => "The contact companies types with ID: " . $contact_companies_type->pro_typ_id . " has been updated to '" . $contact_companies_type->con_com_typ_name . "' succesfully.",
            ], 200);
        }
    }

    // Método para eliminar un tipo de contacto de empresa (actualmente no disponible)
    public function destroy(Contact_Companies_Types $contact_Companies_Types)
    {
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
