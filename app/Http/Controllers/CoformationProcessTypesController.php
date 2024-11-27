<?php

namespace App\Http\Controllers;

use App\Models\Coformation_process_types;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class CoformationProcessTypesController extends Controller
{

    // Método para listar todos los tipos de procesos de coformación
    public function index()
    {
        try {

            // Obtener todos los registros de la tabla 'coformation_process_types'
            $coformation_process_types = Coformation_process_types::all();
            // Si no se encuentran registros, devolver un mensaje
            if ($coformation_process_types->isEmpty()) {
                return response()->json([
                    'status' => false,
                    'message' => 'No registers found.'
                ], 400);
            } else {

                // Devolver los registros en formato JSON
                return response()->json([
                    'status' => true,
                    'data' => $coformation_process_types,
                ], 200);
            }
        } catch (\Throwable $th) {
            // Manejar errores y devolver un mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }

    // Método para crear un nuevo tipo de proceso de coformación
    public function store(Request $request)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'cof_pro_typ_name' => 'required|string|unique:coformation_process_types|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
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

            // Crear un nuevo registro en la tabla 'coformation_process_types'
            $coformation_process_types = new Coformation_process_types($request->input());
            $coformation_process_types->save();

            // Registrar el evento de creación
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla coformation processes", 3, $request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => true,
                'message' => "The process type '" . $coformation_process_types->cof_pro_typ_name . "' has been added succesfully."
            ], 200);
        }
    }

    // Método para mostrar un tipo de proceso de coformación específico
    public function show($coformation_process_types)
    {

        // Buscar el tipo de proceso de coformación por ID
        $coformation_process_types = Coformation_process_types::find($coformation_process_types);

        // Si no se encuentra, devolver un mensaje de error
        if (!$coformation_process_types) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the coformation process type you are looking for'],
            ], 400);
        } else {

            // Devolver el tipo de proceso de coformación en formato JSON
            return response()->json([
                'status' => true,
                'data' => $coformation_process_types,
            ], 200);
        }
    }

     // Método para actualizar un tipo de proceso de coformación
    public function update(Request $request, $id)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'cof_pro_typ_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users',
        ];

        // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla o el nombre ya existe, devolver un mensaje de error
        if ($validator->fails()) {

            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {

            // Buscar el tipo de proceso de coformación por ID
            $coformation_process_types = Coformation_process_types::find($id);

            // Actualizar el registro en la tabla 'coformation_process_types'
            $coformation_process_types->cof_pro_typ_name = $request->cof_pro_typ_name;
            $coformation_process_types->save();

             // Validar que el nombre del tipo de proceso de coformación no exista ya en otro registro
            $validate = Controller::validate_exists($request->cof_pro_typ_name, 'coformation_process_types', 'cof_pro_typ_name', 'cof_pro_typ_id', $id);

           // Si la validación falla o el nombre ya existe, devolver un mensaje de error
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => False,
                    'message' => $msg
                ]);
            }

             // Registrar el evento de actualización
            Controller::NewRegisterTrigger("Se realizo una edición en la tabla process type", 1, $request->use_id);
             // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => true,
                'data' => "The coformation process type with ID: " . $coformation_process_types->cof_pro_typ_id . " has been updated to '" . $coformation_process_types->cof_pro_typ_name . "' succesfully.",
            ], 200);
        }
    }

    // Método para eliminar un tipo de proceso de coformación (actualmente no disponible)
    public function destroy()
    {
        return response()->json([
            'status' => True,
            'message' => 'Function not available.'
        ], 200);
    }
}
